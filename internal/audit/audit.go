// Package audit writes append-only structured metadata events. It must never
// receive tokens, tickets, private keys or terminal content.
package audit

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
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

// Logger records events to a slog handler and an optional in-memory ring for
// tests and the admin view.
type Logger struct {
	log  *slog.Logger
	mu   sync.Mutex
	ring []Event
	max  int
}

// New creates a Logger writing JSON lines to w.
func New(w io.Writer) *Logger {
	return &Logger{log: slog.New(slog.NewJSONHandler(w, nil)).With("log", "audit"), max: 1000}
}

// Record appends an event.
func (l *Logger) Record(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	attrs := []slog.Attr{slog.String("action", e.Action), slog.String("result", e.Result)}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, slog.String(k, v))
		}
	}
	add("actor", e.Actor)
	add("target", e.Target)
	add("session_id", e.SessionID)
	add("attempt_id", e.AttemptID)
	add("reason", e.Reason)
	if e.Revision != 0 {
		attrs = append(attrs, slog.Uint64("policy_revision", e.Revision))
	}
	for k, v := range e.Extra {
		attrs = append(attrs, slog.Any(k, v))
	}
	l.log.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
	l.mu.Lock()
	l.ring = append(l.ring, e)
	if len(l.ring) > l.max {
		l.ring = l.ring[len(l.ring)-l.max:]
	}
	l.mu.Unlock()
}

// Recent returns a copy of the most recent events.
func (l *Logger) Recent() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.ring...)
}
