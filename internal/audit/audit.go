// Package audit persists append-only structured metadata events, one JSON
// object per line in a file per UTC day (<dir>/YYYY-MM-DD.jsonl), similar to
// Teleport's file audit log. Search reads the same files; there is no
// in-memory copy. Events must never carry tokens, tickets, private keys or
// terminal content.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Actor     string         `json:"actor,omitempty"`
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
	// Dir holds the daily files. Created with mode 0700 if missing.
	Dir string
	// Retention deletes daily files whose whole day is older than this.
	// Zero keeps everything.
	Retention time.Duration
	// Mirror optionally receives a copy of every line (e.g. stdout for a log
	// collector). Mirror errors are ignored.
	Mirror io.Writer
	// OnError reports write failures; the event is then lost on disk.
	OnError func(error)
	// Now is for tests.
	Now func() time.Time
}

const fileSuffix = ".jsonl"

// ErrClosed is reported through OnError for events recorded after Close.
var ErrClosed = errors.New("audit: logger closed")

// Logger appends events to the current day's file.
type Logger struct {
	cfg    Config
	mu     sync.Mutex
	day    string
	file   *os.File
	closed bool
}

// Open prepares dir and applies retention.
func Open(cfg Config) (*Logger, error) {
	if cfg.Dir == "" {
		return nil, errors.New("audit: dir is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// The directory is dedicated to audit files; keep it owner-only even if
	// it already existed with wider permissions.
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	l := &Logger{cfg: cfg}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.rotateLocked(cfg.Now().UTC()); err != nil {
		return nil, err
	}
	return l, nil
}

func dayOf(t time.Time) string { return t.UTC().Format(time.DateOnly) }

func (l *Logger) rotateLocked(now time.Time) error {
	day := dayOf(now)
	if l.file != nil && day == l.day {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(l.cfg.Dir, day+fileSuffix), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if l.file != nil {
		_ = l.file.Close()
	}
	l.file, l.day = f, day
	l.pruneLocked(now)
	return nil
}

// pruneLocked removes files for days that ended before now-Retention.
func (l *Logger) pruneLocked(now time.Time) {
	if l.cfg.Retention <= 0 {
		return
	}
	cutoff := now.Add(-l.cfg.Retention)
	for _, day := range l.days() {
		d, _ := time.Parse(time.DateOnly, day)
		if d.Add(24 * time.Hour).Before(cutoff) {
			_ = os.Remove(filepath.Join(l.cfg.Dir, day+fileSuffix))
		}
	}
}

// days lists the stored days in ascending order.
func (l *Logger) days() []string {
	entries, _ := os.ReadDir(l.cfg.Dir)
	var out []string
	for _, e := range entries {
		day, ok := strings.CutSuffix(e.Name(), fileSuffix)
		if !ok || e.IsDir() {
			continue
		}
		if _, err := time.Parse(time.DateOnly, day); err == nil {
			out = append(out, day)
		}
	}
	sort.Strings(out)
	return out
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Record appends an event. Each line is written with a single write on an
// O_APPEND file, so readers never observe interleaved events.
func (l *Logger) Record(e Event) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
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
	if l.closed {
		l.fail(ErrClosed)
	} else if err := l.rotateLocked(now); err != nil {
		l.fail(err)
	} else if _, err := l.file.Write(line); err != nil {
		l.fail(fmt.Errorf("audit: write: %w", err))
	}
	if l.cfg.Mirror != nil {
		_, _ = l.cfg.Mirror.Write(line)
	}
}

func (l *Logger) fail(err error) {
	if l.cfg.OnError != nil {
		l.cfg.OnError(err)
	}
}

// Close closes the current file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
