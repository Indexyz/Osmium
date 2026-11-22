package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

func open(t *testing.T, dir string, c *clock, retention time.Duration) *Logger {
	t.Helper()
	l, err := Open(Config{Dir: dir, Now: c.now, Retention: retention, OnError: func(err error) { t.Errorf("audit error: %v", err) }})
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
		q.From = t0.Add(-48 * time.Hour)
	}
	if q.To.IsZero() {
		q.To = t0.Add(48 * time.Hour)
	}
	if q.Limit == 0 {
		q.Limit = MaxLimit
	}
	p, err := l.Search(q)
	if err != nil {
		t.Fatal(err)
	}
	return p.Events
}

func TestPersistsAcrossRestartAndDays(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0}
	l := open(t, dir, c, 0)
	l.Record(Event{Action: "session.create", Result: "ok", Actor: "user:a", SessionID: "s1"})
	c.add(2 * time.Minute) // crosses UTC midnight
	l.Record(Event{Action: "session.end", Result: "closed", Actor: "user:a", SessionID: "s1"})
	_ = l.Close()

	l2 := open(t, dir, c, 0) // restart: same files, appended
	l2.Record(Event{Action: "session.create", Result: "ok", Actor: "user:b", SessionID: "s2"})

	got := all(t, l2, Query{})
	if len(got) != 3 || got[0].SessionID != "s1" || got[1].Action != "session.end" || got[2].SessionID != "s2" {
		t.Fatalf("got %+v", got)
	}
	if got[0].ID == "" || got[0].ID == got[1].ID || got[0].Time.Location() != time.UTC {
		t.Fatalf("ids/time: %+v", got)
	}
	for _, name := range []string{"2026-11-13.jsonl", "2026-11-14.jsonl"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", name, st.Mode())
		}
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode())
	}
}

func TestFiltersAndTimeRange(t *testing.T) {
	c := &clock{t: t0}
	l := open(t, t.TempDir(), c, 0)
	l.Record(Event{Action: "ca.sign", Result: "ok", Actor: "user:a", SessionID: "s1"})
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
	// [From, To) is half-open.
	if got := all(t, l, Query{From: t0.Add(time.Second), To: t0.Add(2 * time.Second)}); len(got) != 1 || got[0].Actor != "user:b" {
		t.Fatalf("range: %+v", got)
	}
}

func TestCursorPagination(t *testing.T) {
	c := &clock{t: t0}
	l := open(t, t.TempDir(), c, 0)
	for i := 0; i < 7; i++ {
		l.Record(Event{Action: "x", Result: "ok", Reason: string(rune('a' + i))})
		c.add(30 * time.Second) // spreads over two daily files
	}
	var seen []string
	q := Query{From: t0.Add(-time.Hour), To: t0.Add(time.Hour), Limit: 3}
	for pages := 0; ; pages++ {
		p, err := l.Search(q)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Events {
			seen = append(seen, e.Reason)
		}
		if p.Next == "" {
			break
		}
		if pages > 5 {
			t.Fatal("pagination does not terminate")
		}
		q.Cursor = p.Next
	}
	if strings.Join(seen, "") != "abcdefg" {
		t.Fatalf("pages yielded %q", seen)
	}
}

func TestRetentionPrunesOldDays(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0}
	l := open(t, dir, c, 48*time.Hour)
	l.Record(Event{Action: "old", Result: "ok"})
	c.add(4 * 24 * time.Hour)
	l.Record(Event{Action: "new", Result: "ok"}) // rotation triggers pruning
	if _, err := os.Stat(filepath.Join(dir, "2026-11-13.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("old day not pruned: %v", err)
	}
	got := all(t, l, Query{From: t0.Add(-time.Hour), To: t0.Add(5 * 24 * time.Hour)})
	if len(got) != 1 || got[0].Action != "new" {
		t.Fatalf("got %+v", got)
	}
}

func TestTornAndCorruptLines(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: t0}
	l := open(t, dir, c, 0)
	l.Record(Event{Action: "a", Result: "ok"})
	f, _ := os.OpenFile(filepath.Join(dir, "2026-11-13.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("not json\n")
	_, _ = f.WriteString(strings.Repeat("x", maxLine+10) + "\n")
	_, _ = f.WriteString(`{"action":"partial"`) // no newline: a write in progress
	_ = f.Close()
	got := all(t, l, Query{})
	if len(got) != 1 || got[0].Action != "a" {
		t.Fatalf("got %+v", got)
	}
}

func TestBadQueries(t *testing.T) {
	l := open(t, t.TempDir(), &clock{t: t0}, 0)
	for _, q := range []Query{
		{},
		{From: t0, To: t0, Limit: 1},
		{From: t0, To: t0.Add(time.Hour), Limit: 0},
		{From: t0, To: t0.Add(time.Hour), Limit: MaxLimit + 1},
		{From: t0, To: t0.Add(time.Hour), Limit: 1, Cursor: "!!"},
		{From: t0, To: t0.Add(time.Hour), Limit: 1, Cursor: "MjAyNi0xMS0xMzotMQ"}, // offset -1
	} {
		if _, err := l.Search(q); !errors.Is(err, ErrBadQuery) {
			t.Errorf("%+v: err %v", q, err)
		}
	}
}

func TestMirrorAndConcurrentWrites(t *testing.T) {
	var mirror bytes.Buffer
	var mu sync.Mutex
	l, err := Open(Config{Dir: t.TempDir(), Mirror: writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return mirror.Write(p) })})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.Record(Event{Action: "c", Result: "ok"}) }()
	}
	wg.Wait()
	now := time.Now()
	p, err := l.Search(Query{From: now.Add(-time.Hour), To: now.Add(time.Hour), Limit: MaxLimit})
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
