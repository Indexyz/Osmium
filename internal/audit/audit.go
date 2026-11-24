// Package audit persists append-only structured metadata events as JSON lines,
// similar to Teleport's file audit log. Events are queued asynchronously and
// flushed in batches by a dedicated single writer goroutine so bursty fleets
// (50k+ devices) never stall hot request/hub locks on disk I/O. Search and
// Close flush pending batches first for read-your-writes consistency.
package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/indexyz/osmium/internal/tunnel"
)

// Event is one audit record.
type Event struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Actor     string         `json:"actor,omitempty"`
	User      string         `json:"user,omitempty"` // display name; Actor is the identity
	Action    string         `json:"action"`
	Result    string         `json:"result"`
	Target    string         `json:"target,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	AttemptID string         `json:"attempt_id,omitempty"`
	Revision  uint64         `json:"policy_revision,omitempty"`
	Reason    string         `json:"reason,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// Config configures a Logger.
type Config struct {
	// Dir holds local segments: all of them without a Store, otherwise only
	// those not yet uploaded. Created with mode 0700.
	Dir string
	// ServerID is part of every segment name so replicas never collide.
	ServerID string
	// Store, if set, receives sealed segments.
	Store Store
	// SegmentInterval seals the open segment after this long (always at UTC
	// midnight). Zero means daily. It bounds what is only on local disk.
	SegmentInterval time.Duration
	// SegmentMaxBytes seals the open segment once it reaches this size.
	SegmentMaxBytes int64
	// Retention deletes whole days older than this, locally and in the
	// Store. Zero keeps everything.
	Retention time.Duration
	// QueueSize bounds the asynchronous event queue (default 16384).
	QueueSize int
	// FlushInterval bounds batching latency before writing to disk (default 100ms).
	FlushInterval time.Duration
	// Mirror optionally receives a copy of every line (e.g. stdout for a log
	// collector). Mirror errors are ignored.
	Mirror io.Writer
	// OnBatch optionally receives each flushed batch of events (e.g. to index
	// into embedded SQLite WAL in a single transaction).
	OnBatch func([]Event) error
	// SearchIndex optionally answers Search queries from a local database index.
	// Returning handled=false falls back to segment scanning.
	SearchIndex func(ctx context.Context, q Query) (Page, bool, error)
	// OnError reports write, queue overflow and upload failures.
	OnError func(error)
	// Now is for tests.
	Now func() time.Time
}

// ErrClosed is reported through OnError for events recorded after Close.
var ErrClosed = errors.New("audit: logger closed")

// ErrQueueFull is reported through OnError when the async buffer is saturated.
var ErrQueueFull = errors.New("audit: queue full; event dropped")

const (
	uploadTick        = 30 * time.Second
	uploadTimeout     = 30 * time.Second
	defaultQueueSize  = 16384
	defaultBatchMax   = 256
	defaultFlushEvery = 100 * time.Millisecond
)

type segment struct {
	name  string
	start time.Time
	size  int64
	file  *os.File
}

type queuedRecord struct {
	event Event
	line  []byte
	now   time.Time
}

// Logger appends events to the open segment asynchronously in batches.
type Logger struct {
	cfg Config

	// stateMu guards closed and openSegName only; never held during disk I/O.
	stateMu     sync.Mutex
	closed      bool
	openSegName string

	queue     chan queuedRecord
	flushCh   chan chan struct{}
	sealCh    chan chan struct{}
	stopWrite chan struct{}
	writeDone chan struct{}

	// Owned exclusively by writerLoop:
	seg       *segment
	lastStart time.Time

	uploadMu   sync.Mutex // serializes uploads and pruning
	lastPrune  time.Time
	wake       chan struct{}
	stop       chan struct{}
	uploadDone chan struct{}
}

// Open prepares the directory, starts the async batch writer and, with a Store,
// starts the uploader. Segments left by a previous run are uploaded too.
func Open(cfg Config) (*Logger, error) {
	if cfg.Dir == "" {
		return nil, errors.New("audit: dir is required")
	}
	if cfg.ServerID == "" {
		cfg.ServerID = "osmium"
	}
	if !tunnel.ValidID(cfg.ServerID) {
		return nil, fmt.Errorf("audit: invalid server id %q", cfg.ServerID)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushEvery
	}
	// The directory is dedicated to audit files; keep it owner-only even if
	// it already existed with wider permissions.
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	l := &Logger{
		cfg:        cfg,
		queue:      make(chan queuedRecord, cfg.QueueSize),
		flushCh:    make(chan chan struct{}, 16),
		sealCh:     make(chan chan struct{}, 4),
		stopWrite:  make(chan struct{}),
		writeDone:  make(chan struct{}),
		wake:       make(chan struct{}, 1),
		stop:       make(chan struct{}),
		uploadDone: make(chan struct{}),
	}
	go l.writerLoop()
	if cfg.Store != nil {
		l.wake <- struct{}{} // upload leftovers from a previous run
		go l.uploader()
	} else {
		close(l.uploadDone)
		l.prune(context.Background())
	}
	return l, nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Record enqueues an event for batched disk persistence without holding a disk
// I/O lock on the caller goroutine.
func (l *Logger) Record(e Event) {
	if l == nil {
		return
	}
	now := l.cfg.Now().UTC()
	if e.Time.IsZero() {
		e.Time = now
	}
	e.Time = e.Time.UTC()
	if e.ID == "" {
		e.ID = newID()
	}
	line, err := json.Marshal(e)
	if err != nil {
		l.fail(fmt.Errorf("audit: encode %s: %w", e.Action, err))
		return
	}
	line = append(line, '\n')

	l.stateMu.Lock()
	if l.closed {
		l.stateMu.Unlock()
		l.fail(ErrClosed)
		if l.cfg.Mirror != nil {
			_, _ = l.cfg.Mirror.Write(line)
		}
		return
	}
	select {
	case l.queue <- queuedRecord{event: e, line: line, now: now}:
	default:
		l.stateMu.Unlock()
		l.fail(ErrQueueFull)
		if l.cfg.Mirror != nil {
			_, _ = l.cfg.Mirror.Write(line)
		}
		return
	}
	l.stateMu.Unlock()
}

// Flush blocks until all events enqueued prior to the call have been written
// to disk (and delivered to OnBatch / Mirror).
func (l *Logger) Flush() {
	if l == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case l.flushCh <- ack:
		select {
		case <-ack:
		case <-l.writeDone:
		}
	case <-l.writeDone:
	}
}

func (l *Logger) sealAsync() {
	ack := make(chan struct{})
	select {
	case l.sealCh <- ack:
		select {
		case <-ack:
		case <-l.writeDone:
		}
	case <-l.writeDone:
	}
}

func (l *Logger) writerLoop() {
	defer close(l.writeDone)
	batch := make([]queuedRecord, 0, defaultBatchMax)
	var tick *time.Ticker
	if l.cfg.Store != nil {
		interval := uploadTick
		if l.cfg.SegmentInterval > 0 && l.cfg.SegmentInterval/2 < interval {
			interval = l.cfg.SegmentInterval / 2
		}
		if interval < 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}
		tick = time.NewTicker(interval)
		defer tick.Stop()
	}
	var tickC <-chan time.Time
	if tick != nil {
		tickC = tick.C
	}

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		l.writeBatch(batch)
		batch = batch[:0]
	}

	drainAll := func() {
		for {
			select {
			case item := <-l.queue:
				batch = append(batch, item)
				if len(batch) >= defaultBatchMax {
					flushBatch()
				}
			default:
				flushBatch()
				return
			}
		}
	}

	for {
		select {
		case item := <-l.queue:
			batch = append(batch, item)
			// Opportunistically drain queued records up to defaultBatchMax.
		DRAIN:
			for len(batch) < defaultBatchMax {
				select {
				case next := <-l.queue:
					batch = append(batch, next)
				default:
					break DRAIN
				}
			}
			flushBatch()

		case ack := <-l.flushCh:
			drainAll()
			close(ack)

		case ack := <-l.sealCh:
			drainAll()
			l.sealOwned()
			close(ack)

		case <-tickC:
			drainAll()
			if l.seg != nil && l.dueOwned(l.cfg.Now().UTC()) {
				l.sealOwned()
			}

		case <-l.stopWrite:
			drainAll()
			l.sealOwned()
			return
		}
	}
}

func (l *Logger) writeBatch(batch []queuedRecord) {
	var buf bytes.Buffer
	var events []Event
	if l.cfg.OnBatch != nil {
		events = make([]Event, 0, len(batch))
	}

	flushBuf := func() {
		if buf.Len() == 0 || l.seg == nil {
			return
		}
		n, err := l.seg.file.Write(buf.Bytes())
		l.seg.size += int64(n)
		buf.Reset()
		if err != nil {
			l.fail(fmt.Errorf("audit: write: %w", err))
		}
	}

	for _, item := range batch {
		if l.seg != nil && l.dueOwned(item.now) {
			flushBuf()
			l.sealOwned()
		}
		if l.seg == nil {
			if err := l.openSegOwned(item.now); err != nil {
				l.fail(err)
				if l.cfg.Mirror != nil {
					_, _ = l.cfg.Mirror.Write(item.line)
				}
				continue
			}
		}
		buf.Write(item.line)
		// If size-based rotation is tiny (e.g. tests with SegmentMaxBytes=1),
		// flush immediately so each record rotates accurately.
		if l.cfg.SegmentMaxBytes > 0 && l.seg.size+int64(buf.Len()) >= l.cfg.SegmentMaxBytes {
			flushBuf()
		}
		if l.cfg.Mirror != nil {
			_, _ = l.cfg.Mirror.Write(item.line)
		}
		if l.cfg.OnBatch != nil {
			events = append(events, item.event)
		}
	}
	flushBuf()
	if l.cfg.OnBatch != nil && len(events) > 0 {
		if err := l.cfg.OnBatch(events); err != nil {
			l.fail(fmt.Errorf("audit: index batch: %w", err))
		}
	}
}

func (l *Logger) dueOwned(now time.Time) bool {
	s := l.seg
	return dayOf(now) != dayOf(s.start) ||
		(l.cfg.SegmentInterval > 0 && now.Sub(s.start) >= l.cfg.SegmentInterval) ||
		(l.cfg.SegmentMaxBytes > 0 && s.size >= l.cfg.SegmentMaxBytes)
}

func (l *Logger) openSegOwned(now time.Time) error {
	start := now
	if !start.After(l.lastStart) {
		start = l.lastStart.Add(time.Nanosecond) // keep names unique and ordered
	}
	var (
		name string
		f    *os.File
		err  error
	)
	for range 1000 {
		name = segName(start, l.cfg.ServerID)
		path := filepath.Join(l.cfg.Dir, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o600)
		if !errors.Is(err, fs.ErrExist) {
			break
		}
		start = start.Add(time.Nanosecond)
	}
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	l.seg = &segment{name: name, start: start, file: f}
	l.lastStart = start
	l.stateMu.Lock()
	l.openSegName = name
	l.stateMu.Unlock()
	return nil
}

func (l *Logger) sealOwned() {
	if l.seg == nil {
		return
	}
	_ = l.seg.file.Close()
	l.seg = nil
	l.stateMu.Lock()
	l.openSegName = ""
	l.stateMu.Unlock()
	if l.cfg.Store == nil {
		go l.prune(context.Background())
		return
	}
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *Logger) fail(err error) {
	if l.cfg.OnError != nil {
		l.cfg.OnError(err)
	}
}

// openName is the name of the segment being written, if any.
func (l *Logger) openName() string {
	l.Flush()
	return l.openNameFast()
}

func (l *Logger) openNameFast() string {
	l.stateMu.Lock()
	n := l.openSegName
	l.stateMu.Unlock()
	return n
}

// Sync flushes pending events, seals the open segment and uploads everything
// pending. Without a Store it only flushes and seals.
func (l *Logger) Sync(ctx context.Context) error {
	l.sealAsync()
	if l.cfg.Store == nil {
		return nil
	}
	return l.upload(ctx)
}

// Close stops accepting new events, flushes and seals pending local writes,
// and with a Store performs a final upload attempt.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.stateMu.Lock()
	if l.closed {
		l.stateMu.Unlock()
		return nil
	}
	l.closed = true
	l.stateMu.Unlock()

	close(l.stopWrite)
	<-l.writeDone

	close(l.stop)
	<-l.uploadDone
	if l.cfg.Store == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), uploadTimeout)
	defer cancel()
	return l.upload(ctx)
}

func (l *Logger) uploader() {
	defer close(l.uploadDone)
	tick := uploadTick
	if l.cfg.SegmentInterval > 0 && l.cfg.SegmentInterval/2 < tick {
		tick = l.cfg.SegmentInterval / 2
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
		case <-l.wake:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*uploadTimeout)
		if err := l.upload(ctx); err != nil {
			l.fail(err)
		}
		cancel()
	}
}

// upload pushes every sealed local segment, oldest first, removing each one
// locally only after the Store accepted it. It stops at the first failure.
func (l *Logger) upload(ctx context.Context) error {
	l.uploadMu.Lock()
	defer l.uploadMu.Unlock()
	open := l.openNameFast()
	for _, day := range l.localDays() {
		for _, name := range l.localSegs(day) {
			if name == open {
				continue
			}
			if err := l.uploadOne(ctx, name); err != nil {
				return fmt.Errorf("audit: upload %s: %w", name, err)
			}
		}
		_ = os.Remove(filepath.Join(l.cfg.Dir, day)) // only succeeds when empty
	}
	if now := l.cfg.Now(); now.Sub(l.lastPrune) >= time.Hour {
		l.lastPrune = now
		l.pruneLocked(ctx)
	}
	return nil
}

func (l *Logger) uploadOne(ctx context.Context, name string) error {
	path := filepath.Join(l.cfg.Dir, filepath.FromSlash(name))
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(data)
		if err := zw.Close(); err != nil {
			return err
		}
		if err := l.cfg.Store.Put(ctx, name+gzSuffix, buf.Bytes()); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

// prune applies Retention (local-only mode).
func (l *Logger) prune(ctx context.Context) {
	l.uploadMu.Lock()
	defer l.uploadMu.Unlock()
	l.pruneLocked(ctx)
}

// pruneLocked deletes days that ended before now-Retention.
func (l *Logger) pruneLocked(ctx context.Context) {
	if l.cfg.Retention <= 0 {
		return
	}
	cutoff := l.cfg.Now().Add(-l.cfg.Retention)
	expired := func(day string) bool {
		d, _ := time.Parse(time.DateOnly, day)
		return d.Add(24 * time.Hour).Before(cutoff)
	}
	open := l.openNameFast()
	for _, day := range l.localDays() {
		if expired(day) && !strings.HasPrefix(open, day+"/") {
			_ = os.RemoveAll(filepath.Join(l.cfg.Dir, day))
		}
	}
	if l.cfg.Store == nil {
		return
	}
	days, err := l.storeDays(ctx)
	if err != nil {
		l.fail(fmt.Errorf("audit: retention: %w", err))
		return
	}
	for _, day := range days {
		if !expired(day) {
			continue
		}
		names, err := l.cfg.Store.List(ctx, day+"/")
		if err == nil && len(names) > 0 {
			full := make([]string, len(names))
			for i, n := range names {
				full[i] = day + "/" + n
			}
			err = l.cfg.Store.Delete(ctx, full)
		}
		if err != nil {
			l.fail(fmt.Errorf("audit: retention %s: %w", day, err))
		}
	}
}

// localDays lists local day directories in ascending order.
func (l *Logger) localDays() []string {
	entries, _ := os.ReadDir(l.cfg.Dir)
	var out []string
	for _, e := range entries {
		if e.IsDir() && validDay(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// localSegs lists the local segment names of one day in ascending order.
func (l *Logger) localSegs(day string) []string {
	entries, _ := os.ReadDir(filepath.Join(l.cfg.Dir, day))
	var out []string
	for _, e := range entries {
		name := day + "/" + e.Name()
		if _, ok := parseSeg(name); ok && e.Type().IsRegular() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (l *Logger) storeDays(ctx context.Context) ([]string, error) {
	names, err := l.cfg.Store.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if day, ok := strings.CutSuffix(n, "/"); ok && validDay(day) {
			out = append(out, day)
		}
	}
	sort.Strings(out)
	return out, nil
}

// storeSegs lists the uploaded segment names of one day.
func (l *Logger) storeSegs(ctx context.Context, day string) ([]string, error) {
	names, err := l.cfg.Store.List(ctx, day+"/")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if base, ok := strings.CutSuffix(n, gzSuffix); ok {
			if _, ok := parseSeg(day + "/" + base); ok {
				out = append(out, day+"/"+base)
			}
		}
	}
	return out, nil
}
