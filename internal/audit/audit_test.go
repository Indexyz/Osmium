package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// memStore is an in-memory Store with failure injection.
type memStore struct {
	mu   sync.Mutex
	objs map[string][]byte
	fail error
	gets int
}

func newMem() *memStore { return &memStore{objs: map[string][]byte{}} }

func (m *memStore) Put(_ context.Context, name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.objs[name] = append([]byte(nil), data...)
	return nil
}

func (m *memStore) Get(_ context.Context, name string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	if m.fail != nil {
		return nil, m.fail
	}
	b, ok := m.objs[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *memStore) List(_ context.Context, dir string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return nil, m.fail
	}
	seen := map[string]bool{}
	for k := range m.objs {
		rest, ok := strings.CutPrefix(k, dir)
		if !ok {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i+1]
		}
		seen[rest] = true
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (m *memStore) Delete(_ context.Context, names []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range names {
		delete(m.objs, n)
	}
	return nil
}

func (m *memStore) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *memStore) get(k string) []byte { m.mu.Lock(); defer m.mu.Unlock(); return m.objs[k] }

func (m *memStore) setFail(err error) { m.mu.Lock(); m.fail = err; m.mu.Unlock() }

func open(t *testing.T, cfg Config) *Logger {
	t.Helper()
	if cfg.OnError == nil {
		cfg.OnError = func(err error) { t.Errorf("audit error: %v", err) }
	}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

var t0 = time.Date(2026, 11, 13, 23, 59, 0, 0, time.UTC)

func all(t *testing.T, l *Logger, q Query) []Event {
	t.Helper()
	if q.From.IsZero() {
		q.From = t0.Add(-24 * time.Hour)
	}
	if q.To.IsZero() {
		q.To = t0.Add(24 * time.Hour)
	}
	if q.Limit == 0 {
		q.Limit = MaxLimit
	}
	var out []Event
	for i := 0; ; i++ {
		p, err := l.Search(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p.Events...)
		if p.Next == "" {
			return out
		}
		if i > 1000 {
			t.Fatal("pagination does not terminate")
		}
		q.Cursor = p.Next
	}
}

func reasons(evs []Event) string {
	var b strings.Builder
	for _, e := range evs {
		b.WriteString(e.Reason)
	}
	return b.String()
}

func TestSegmentNames(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	n := segName(ts, "osmium-1")
	if n != "2026-01-02/030405.000000006-osmium-1.jsonl" {
		t.Fatal(n)
	}
	if got, ok := parseSeg(n); !ok || !got.Equal(ts) {
		t.Fatal(got, ok)
	}
	for _, bad := range []string{
		"../2026-01-02/030405.000000006-a.jsonl",
		"2026-01-02/../../etc/passwd",
		"2026-01-02/030405.000000006-a/b.jsonl",
		"2026-01-02/030405.000000006-.jsonl",
		"2026-13-02/030405.000000006-a.jsonl",
		"2026-01-02/030405.000000006-a.jsonl.gz",
		"2026-01-02/250405.000000006-a.jsonl",
	} {
		if _, ok := parseSeg(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLocalPersistsAcrossRestartAndDays(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0}
	l := open(t, Config{Dir: dir, ServerID: "s-1", Now: c.now})
	l.Record(Event{Action: "session.create", Result: "ok", Actor: "user:a", SessionID: "s1"})
	c.add(2 * time.Minute) // crosses UTC midnight
	l.Record(Event{Action: "session.end", Result: "closed", Actor: "user:a", SessionID: "s1"})
	_ = l.Close()

	l2 := open(t, Config{Dir: dir, ServerID: "s-1", Now: c.now}) // restart: new segment
	l2.Record(Event{Action: "session.create", Result: "ok", Actor: "user:b", SessionID: "s2"})

	got := all(t, l2, Query{})
	if len(got) != 3 || got[0].SessionID != "s1" || got[1].Action != "session.end" || got[2].SessionID != "s2" {
		t.Fatalf("got %+v", got)
	}
	if got[0].ID == "" || got[0].ID == got[1].ID || got[0].Time.Location() != time.UTC {
		t.Fatalf("ids/time: %+v", got)
	}
	segs := append(l2.localSegs("2026-11-13"), l2.localSegs("2026-11-14")...)
	if len(segs) != 3 {
		t.Fatalf("segments %v", segs)
	}
	if runtime.GOOS != "windows" {
		for _, seg := range segs {
			st, err := os.Stat(filepath.Join(dir, seg))
			if err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v %v", seg, st.Mode(), err)
			}
		}
		for _, d := range []string{dir, filepath.Join(dir, "2026-11-14")} {
			if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
				t.Fatalf("%s mode %v", d, st.Mode())
			}
		}
	}
}

func TestFiltersAndTimeRange(t *testing.T) {
	c := &clock{t: t0}
	l := open(t, Config{Dir: t.TempDir(), Now: c.now})
	l.Record(Event{Action: "ca.sign", Result: "ok", Actor: "user:a", SessionID: "s1", User: "Alice Liddell"})
	c.add(time.Second)
	l.Record(Event{Action: "session.create", Result: "denied", Actor: "user:b", Target: "host-1/ops"})
	c.add(time.Second)
	l.Record(Event{Action: "ca.sign", Result: "ok", Actor: "user:b", SessionID: "s2"})

	if got := all(t, l, Query{Action: "ca.sign"}); len(got) != 2 {
		t.Fatalf("action: %+v", got)
	}
	if got := all(t, l, Query{Actor: "user:b", Action: "ca.sign"}); len(got) != 1 || got[0].SessionID != "s2" {
		t.Fatalf("actor+action: %+v", got)
	}
	if got := all(t, l, Query{Target: "host-1/ops"}); len(got) != 1 {
		t.Fatalf("target: %+v", got)
	}
	// user= matches the display name (any case) or the internal ID.
	for _, u := range []string{"alice liddell", "a"} {
		if got := all(t, l, Query{User: u}); len(got) != 1 || got[0].SessionID != "s1" {
			t.Fatalf("user %q: %+v", u, got)
		}
	}
	if got := all(t, l, Query{User: "alice"}); len(got) != 0 {
		t.Fatalf("partial name matched: %+v", got)
	}
	// [From, To) is half-open.
	if got := all(t, l, Query{From: t0.Add(time.Second), To: t0.Add(2 * time.Second)}); len(got) != 1 || got[0].Actor != "user:b" {
		t.Fatalf("range: %+v", got)
	}
}

func TestCursorPagination(t *testing.T) {
	c := &clock{t: t0}
	l := open(t, Config{Dir: t.TempDir(), Now: c.now, SegmentMaxBytes: 300})
	for i := 0; i < 7; i++ {
		l.Record(Event{Action: "x", Result: "ok", Reason: string(rune('a' + i))})
		c.add(30 * time.Second) // spreads over two days and several segments
	}
	q := Query{From: t0.Add(-time.Hour), To: t0.Add(time.Hour), Limit: 3}
	p, err := l.Search(context.Background(), q)
	if err != nil || len(p.Events) != 3 || p.Next == "" {
		t.Fatalf("first page %+v %v", p, err)
	}
	if got := reasons(all(t, l, q)); got != "abcdefg" {
		t.Fatalf("pages yielded %q", got)
	}
}

func TestLocalRetentionPrunesOldDays(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0}
	l := open(t, Config{Dir: dir, Now: c.now, Retention: 48 * time.Hour})
	l.Record(Event{Action: "old", Result: "ok"})
	c.add(4 * 24 * time.Hour)
	l.Record(Event{Action: "new", Result: "ok"}) // the day change seals and prunes
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "2026-11-13")); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old day not pruned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := all(t, l, Query{From: t0.Add(3 * 24 * time.Hour), To: t0.Add(5 * 24 * time.Hour)})
	if len(got) != 1 || got[0].Action != "new" {
		t.Fatalf("got %+v", got)
	}
}

func TestTornAndCorruptLines(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0}
	l := open(t, Config{Dir: dir, Now: c.now})
	l.Record(Event{Action: "a", Result: "ok"})
	f, _ := os.OpenFile(filepath.Join(dir, l.openName()), os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("not json\n")
	_, _ = f.WriteString(strings.Repeat("x", maxLine+10) + "\n")
	_, _ = f.WriteString(`{"action":"partial"`) // no newline: a write in progress
	_ = f.Close()
	// Stray files in the directory are ignored.
	_ = os.WriteFile(filepath.Join(dir, "2026-11-13", "notes.txt"), []byte("x\n"), 0o600)
	got := all(t, l, Query{})
	if len(got) != 1 || got[0].Action != "a" {
		t.Fatalf("got %+v", got)
	}
}

func TestBadQueries(t *testing.T) {
	l := open(t, Config{Dir: t.TempDir(), Now: (&clock{t: t0}).now})
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, q := range []Query{
		{},
		{From: t0, To: t0, Limit: 1},
		{From: t0, To: t0.Add(time.Hour), Limit: 0},
		{From: t0, To: t0.Add(time.Hour), Limit: MaxLimit + 1},
		{From: t0, To: t0.Add(MaxRange + time.Second), Limit: 1},
		{From: t0, To: t0.Add(time.Hour), Limit: 1, Cursor: "!!"},
		{From: t0, To: t0.Add(time.Hour), Limit: 1, Cursor: enc("2026-11-13/235900.000000000-osmium.jsonl|-2")},
		{From: t0, To: t0.Add(time.Hour), Limit: 1, Cursor: enc("../../etc/passwd|0")},
		{From: t0, To: t0.Add(time.Hour), Limit: 1, Cursor: enc("2026-11-13/x|0")},
	} {
		if _, err := l.Search(context.Background(), q); !errors.Is(err, ErrBadQuery) {
			t.Errorf("%+v: err %v", q, err)
		}
	}
	if _, err := Open(Config{Dir: t.TempDir(), ServerID: "a/b"}); err == nil {
		t.Error("server id with a slash accepted")
	}
}

func TestMirrorAndConcurrentWrites(t *testing.T) {
	var mirror bytes.Buffer
	var mu sync.Mutex
	l := open(t, Config{Dir: t.TempDir(), Mirror: writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return mirror.Write(p) })})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.Record(Event{Action: "c", Result: "ok"}) }()
	}
	wg.Wait()
	now := time.Now()
	p, err := l.Search(context.Background(), Query{From: now.Add(-time.Hour), To: now.Add(time.Hour), Limit: MaxLimit})
	if err != nil || len(p.Events) != 50 {
		t.Fatalf("%d events, err %v", len(p.Events), err)
	}
	lines := strings.Split(strings.TrimSpace(mirror.String()), "\n")
	var e Event
	if len(lines) != 50 || json.Unmarshal([]byte(lines[0]), &e) != nil || e.Action != "c" {
		t.Fatalf("mirror: %d lines", len(lines))
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestRecordAfterCloseDoesNotReopen(t *testing.T) {
	dir := t.TempDir()
	var errs []error
	l, err := Open(Config{Dir: dir, Now: (&clock{t: t0}).now, OnError: func(err error) { errs = append(errs, err) }})
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	_ = os.RemoveAll(dir)
	l.Record(Event{Action: "late", Result: "ok"})
	if len(errs) != 1 || !errors.Is(errs[0], ErrClosed) {
		t.Fatalf("errs %v", errs)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("closed logger recreated files")
	}
}

// --- object storage ---

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestUploadsSealedSegments(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0.Add(-time.Hour)}
	st := newMem()
	l := open(t, Config{Dir: dir, ServerID: "osm-1", Store: st, Now: c.now, SegmentInterval: 5 * time.Minute})
	l.Record(Event{Action: "a", Result: "ok", Reason: "a"})
	c.add(time.Minute)
	l.Record(Event{Action: "b", Result: "ok", Reason: "b"}) // same segment
	c.add(5 * time.Minute)
	l.Record(Event{Action: "c", Result: "ok", Reason: "c"}) // interval: new segment
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys := st.keys()
	if len(keys) != 2 || keys[0] != "2026-11-13/225900.000000000-osm-1.jsonl.gz" {
		t.Fatalf("keys %v", keys)
	}
	if body := gunzip(t, st.get(keys[0])); strings.Count(body, "\n") != 2 || !strings.Contains(body, `"action":"b"`) {
		t.Fatalf("object body %q", body)
	}
	if segs := l.localSegs("2026-11-13"); len(segs) != 0 {
		t.Fatalf("local copies left: %v", segs)
	}
	if got := reasons(all(t, l, Query{})); got != "abc" {
		t.Fatalf("search from store: %q", got)
	}
	if got := all(t, l, Query{Action: "b"}); len(got) != 1 {
		t.Fatalf("filter: %+v", got)
	}
}

func TestSizeRotation(t *testing.T) {
	c := &clock{t: t0.Add(-time.Hour)}
	st := newMem()
	l := open(t, Config{Dir: t.TempDir(), Store: st, Now: c.now, SegmentMaxBytes: 1})
	for i := 0; i < 3; i++ {
		l.Record(Event{Action: "x", Result: "ok"})
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(st.keys()); n != 3 {
		t.Fatalf("%d objects", n)
	}
}

// While the store is down, events stay on local disk and are uploaded once
// it recovers.
func TestStoreOutageKeepsLocalCopy(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0.Add(-time.Hour)}
	st := newMem()
	l := open(t, Config{Dir: dir, Store: st, Now: c.now, OnError: func(error) {}})
	l.Record(Event{Action: "a", Result: "ok", Reason: "a"})
	st.setFail(errors.New("connection refused"))
	if err := l.Sync(context.Background()); err == nil {
		t.Fatal("sync succeeded while store is down")
	}
	if len(l.localSegs("2026-11-13")) != 1 {
		t.Fatal("local copy removed after failed upload")
	}
	// A broken listing is an error rather than a silently partial answer.
	if _, err := l.Search(context.Background(), Query{From: t0.Add(-2 * time.Hour), To: t0, Limit: 10}); err == nil {
		t.Fatal("search hid a store failure")
	}
	st.setFail(nil)
	if got := reasons(all(t, l, Query{})); got != "a" {
		t.Fatalf("local search: %q", got)
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.keys()) != 1 || len(l.localSegs("2026-11-13")) != 0 {
		t.Fatalf("after recovery: store %v local %v", st.keys(), l.localSegs("2026-11-13"))
	}
}

// Segments left by a previous run (e.g. after a crash) are uploaded at start.
func TestLeftoversUploadedOnOpen(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0.Add(-time.Hour)}
	l := open(t, Config{Dir: dir, Now: c.now})
	l.Record(Event{Action: "before", Result: "ok"})
	_ = l.Close()

	st := newMem()
	l2 := open(t, Config{Dir: dir, Store: st, Now: c.now})
	deadline := time.Now().Add(5 * time.Second)
	for len(st.keys()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("leftover segment not uploaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := all(t, l2, Query{}); len(got) != 1 || got[0].Action != "before" {
		t.Fatalf("got %+v", got)
	}
}

// A segment present both locally and in the store (between upload and local
// removal) is returned once.
func TestNoDuplicateDuringUpload(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0.Add(-time.Hour)}
	st := newMem()
	l := open(t, Config{Dir: dir, Store: st, Now: c.now})
	l.Record(Event{Action: "a", Result: "ok"})
	name := l.openName()
	data, _ := os.ReadFile(filepath.Join(dir, name))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	_ = st.Put(context.Background(), name+gzSuffix, buf.Bytes())
	if got := all(t, l, Query{}); len(got) != 1 {
		t.Fatalf("got %d events", len(got))
	}
}

// Remote scans are bounded per call; following the cursor reaches the end.
func TestRemoteScanBudget(t *testing.T) {
	c := &clock{t: t0.Add(-12 * time.Hour)}
	st := newMem()
	l := open(t, Config{Dir: t.TempDir(), Store: st, Now: c.now, SegmentMaxBytes: 1})
	n := maxRemoteSegs + 10
	for i := 0; i < n; i++ {
		l.Record(Event{Action: "x", Result: "ok"})
		c.add(time.Second)
	}
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	q := Query{From: t0.Add(-13 * time.Hour), To: t0, Limit: MaxLimit, Action: "nothing"}
	p, err := l.Search(context.Background(), q)
	if err != nil || len(p.Events) != 0 || p.Next == "" || st.gets != maxRemoteSegs {
		t.Fatalf("page %+v err %v gets %d", p, err, st.gets)
	}
	q.Action = ""
	if got := all(t, l, q); len(got) != n {
		t.Fatalf("%d of %d events", len(got), n)
	}
}

func TestStoreRetention(t *testing.T) {
	c := &clock{t: t0.Add(-time.Hour)}
	st := newMem()
	l := open(t, Config{Dir: t.TempDir(), Store: st, Now: c.now, Retention: 48 * time.Hour})
	l.Record(Event{Action: "old", Result: "ok"})
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = st.Put(context.Background(), "unrelated/keep.txt", []byte("x"))
	c.add(5 * 24 * time.Hour)
	l.Record(Event{Action: "new", Result: "ok"})
	if err := l.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys := st.keys()
	if len(keys) != 2 || !strings.HasPrefix(keys[0], "2026-11-18/") || keys[1] != "unrelated/keep.txt" {
		t.Fatalf("keys %v", keys)
	}
}
