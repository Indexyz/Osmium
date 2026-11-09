package tunnel

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// Registry is the Agent-side per-epoch table of stream attempts. It enforces
// the stream quota, rejects duplicate attempts atomically and remembers
// close-before-open requests as bounded tombstones.
type Registry struct {
	mu         sync.Mutex
	maxStreams int
	maxSeen    int
	tombTTL    time.Duration
	active     map[attemptKey]context.CancelFunc
	seen       map[attemptKey]struct{}
	seenOrder  []attemptKey
	tombstones map[attemptKey]time.Time
	slots      int
	closed     bool
}

type attemptKey struct{ session, attempt string }

// NewRegistry creates a registry allowing maxStreams pending+active streams.
func NewRegistry(maxStreams int) *Registry {
	return &Registry{
		maxStreams: maxStreams,
		maxSeen:    4096,
		tombTTL:    2 * time.Minute,
		active:     map[attemptKey]context.CancelFunc{},
		seen:       map[attemptKey]struct{}{},
		tombstones: map[attemptKey]time.Time{},
	}
}

// Reserve takes a stream slot before any per-stream goroutine is started.
func (r *Registry) Reserve() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slots >= r.maxStreams {
		return false
	}
	r.slots++
	return true
}

// Unreserve returns a slot taken by Reserve.
func (r *Registry) Unreserve() {
	r.mu.Lock()
	r.slots--
	r.mu.Unlock()
}

// Admit registers the attempt with its cancel function.
func (r *Registry) Admit(q OpenRequest, cancel context.CancelFunc) (release func(), err error) {
	k := attemptKey{q.SessionID, q.AttemptID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, coded(CodeCancelled, "registry closed")
	}
	r.gcLocked(time.Now())
	if _, dup := r.seen[k]; dup {
		return nil, coded(CodeDuplicateAttempt, "attempt already used")
	}
	r.rememberLocked(k)
	if _, dead := r.tombstones[k]; dead {
		delete(r.tombstones, k)
		return nil, coded(CodeCancelled, "attempt closed before open")
	}
	r.active[k] = cancel
	return func() {
		r.mu.Lock()
		delete(r.active, k)
		r.mu.Unlock()
	}, nil
}

func (r *Registry) rememberLocked(k attemptKey) {
	r.seen[k] = struct{}{}
	r.seenOrder = append(r.seenOrder, k)
	if len(r.seenOrder) > r.maxSeen {
		old := r.seenOrder[0]
		r.seenOrder = r.seenOrder[1:]
		delete(r.seen, old)
	}
}

func (r *Registry) gcLocked(now time.Time) {
	for k, exp := range r.tombstones {
		if now.After(exp) {
			delete(r.tombstones, k)
		}
	}
}

// Close cancels the attempt if present, otherwise leaves a tombstone so a
// later open of the same attempt is refused. It is idempotent.
func (r *Registry) Close(sessionID, attemptID string) {
	k := attemptKey{sessionID, attemptID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancel, ok := r.active[k]; ok {
		cancel()
		return
	}
	if _, used := r.seen[k]; used {
		return
	}
	r.gcLocked(time.Now())
	if len(r.tombstones) < r.maxSeen {
		r.tombstones[k] = time.Now().Add(r.tombTTL)
	}
}

// CloseAll cancels every attempt; used when the epoch ends.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, c := range r.active {
		c()
	}
}

// Active returns the number of reserved slots (pending + active streams).
func (r *Registry) Active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.slots
}

// AgentOptions configures ServeSSHStream.
type AgentOptions struct {
	Binding      Binding
	Target       string // trusted local config only; explicit loopback IP:port
	OpenTimeout  time.Duration
	DialTimeout  time.Duration
	DrainTimeout time.Duration
	Registry     *Registry
}

// ValidateTarget requires a loopback IP literal and a valid port.
func ValidateTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || ip == nil || !ip.IsLoopback() {
		return errors.New("target must be a configured loopback IP and valid port")
	}
	return nil
}

// RejectStream answers a stream that could not get a slot. It reads the
// prelude under a short deadline so the Gateway gets a stable code.
func RejectStream(st *smux.Stream, code string, timeout time.Duration) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(timeout))
	var q OpenRequest
	if err := ReadPrelude(st, &q); err != nil || !ValidID(q.SessionID) || !ValidID(q.AttemptID) {
		return
	}
	_ = WritePrelude(st, OpenResult{Version: 1, Type: "ssh.open_result", SessionID: q.SessionID, AttemptID: q.AttemptID, Code: code})
}

// ServeSSHStream handles ONE accepted stream whose slot was already reserved.
func ServeSSHStream(parent context.Context, st *smux.Stream, o AgentOptions) error {
	defer st.Close()
	if o.Registry == nil || o.OpenTimeout <= 0 || o.DialTimeout <= 0 || o.DrainTimeout <= 0 {
		return errors.New("registry and positive timeouts required")
	}
	if err := ValidateTarget(o.Target); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := guard(ctx, st, o.OpenTimeout)
	defer stop()
	var q OpenRequest
	if err := ReadPrelude(st, &q); err != nil {
		return err
	}
	reply := func(code string) error {
		return WritePrelude(st, OpenResult{Version: 1, Type: "ssh.open_result", SessionID: q.SessionID, AttemptID: q.AttemptID, OK: code == "", Code: code})
	}
	if err := q.Validate(o.Binding); err != nil {
		if ValidID(q.SessionID) && ValidID(q.AttemptID) {
			_ = reply(ErrorCode(err))
		}
		return err
	}
	release, err := o.Registry.Admit(q, cancel)
	if err != nil {
		code := ErrorCode(err)
		if code == "" {
			code = CodeOpenDenied
		}
		_ = reply(code)
		return err
	}
	defer release()
	d := net.Dialer{Timeout: o.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", o.Target)
	if err != nil {
		if ctx.Err() != nil {
			_ = reply(CodeCancelled)
		} else {
			_ = reply(CodeSSHDialFailed)
		}
		return err
	}
	defer conn.Close()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("expected TCP connection")
	}
	if err := reply(""); err != nil {
		return err
	}
	stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := st.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return Relay(ctx, st, tcp, o.DrainTimeout)
}
