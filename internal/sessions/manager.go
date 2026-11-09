// Package sessions owns the Web SSH session state machine:
// created → waiting_agent → signing → ssh_authenticating → active → closing → closed,
// with failed for unrecoverable errors. Authorization is re-checked at
// creation, before signing and before activation.
package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/sshgateway"
	"github.com/indexyz/osmium/internal/tunnel"
)

// Session states.
const (
	StateCreated           = "created"
	StateWaitingAgent      = "waiting_agent"
	StateSigning           = "signing"
	StateSSHAuthenticating = "ssh_authenticating"
	StateActive            = "active"
	StateClosing           = "closing"
	StateClosed            = "closed"
	StateFailed            = "failed"
)

// Public error codes.
var (
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrUnavailable  = errors.New("unavailable")
	ErrInvalid      = errors.New("invalid request")
	ErrLimitReached = errors.New("session limit reached")
)

// Opener opens acknowledged SSH streams (implemented by agenthub.Hub).
type Opener interface {
	OpenStream(ctx context.Context, hostID, sessionID, attemptID string) (*agenthub.Stream, error)
	CloseAttempt(agentID string, epoch uint64, sessionID, attemptID, reason string)
	Status(host *authz.Host) string
}

// Config holds session policy knobs. Values marked "pending product decision"
// in docs/10 are configurable here rather than hard-coded.
type Config struct {
	AttachTimeout      time.Duration // created → must attach within
	SSHHandshake       time.Duration
	MaxSessionDuration time.Duration // 0 = unlimited
	MaxPerUser         int
	MaxTotal           int
	RevokeActive       bool // close active sessions when access is revoked
	Retention          time.Duration
}

func (c *Config) defaults() {
	if c.AttachTimeout <= 0 {
		c.AttachTimeout = 60 * time.Second
	}
	if c.SSHHandshake <= 0 {
		c.SSHHandshake = 15 * time.Second
	}
	if c.MaxPerUser <= 0 {
		c.MaxPerUser = 10
	}
	if c.MaxTotal <= 0 {
		c.MaxTotal = 1000
	}
	if c.Retention <= 0 {
		c.Retention = time.Hour
	}
}

// Attempt records audit metadata of one connection attempt. No private key
// or token is ever stored.
type Attempt struct {
	ID                   string    `json:"id"`
	AgentID              string    `json:"agent_id"`
	Epoch                uint64    `json:"connection_epoch"`
	DataTunnelID         string    `json:"data_tunnel_id"`
	StreamID             uint32    `json:"smux_stream_id"`
	CertSerial           uint64    `json:"cert_serial,omitempty"`
	CertKeyID            string    `json:"cert_key_id,omitempty"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint,omitempty"`
	ValidAfter           time.Time `json:"valid_after,omitzero"`
	ValidBefore          time.Time `json:"valid_before,omitzero"`
}

// Session is one Web SSH session resource.
type Session struct {
	ID        string
	Subject   authz.Subject
	HostID    string
	Login     string
	CreatedAt time.Time

	mu             sync.Mutex
	state          string
	stateVersion   uint64
	endReason      string
	activatedAt    time.Time
	endedAt        time.Time
	policyRevision uint64
	rows, cols     int
	attached       bool
	attempt        *Attempt
	ctx            context.Context
	cancel         context.CancelCauseFunc
	sshSession     *ssh.Session
	stdin          io.WriteCloser
	listeners      []func(state string)
	done           chan struct{}
}

// View is the public projection of a session.
type View struct {
	ID         string    `json:"id"`
	HostID     string    `json:"host_id"`
	LoginUser  string    `json:"login_user"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	TermPath   string    `json:"terminal_path"`
	EndReason  *string   `json:"end_reason"`
	UserID     string    `json:"-"`
	Attempt    *Attempt  `json:"-"`
	Version    uint64    `json:"-"`
	ActivateAt time.Time `json:"-"`
}

// View returns a snapshot.
func (s *Session) View() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{ID: s.ID, HostID: s.HostID, LoginUser: s.Login, State: s.state, CreatedAt: s.CreatedAt,
		TermPath: "/api/v1/ssh-sessions/" + s.ID + "/terminal", UserID: s.Subject.UserID, Version: s.stateVersion, ActivateAt: s.activatedAt}
	if s.endReason != "" {
		r := s.endReason
		v.EndReason = &r
	}
	if s.attempt != nil {
		a := *s.attempt
		v.Attempt = &a
	}
	return v
}

// State returns the current state.
func (s *Session) State() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Done is closed once the session reached a final state.
func (s *Session) Done() <-chan struct{} { return s.done }

func final(st string) bool { return st == StateClosed || st == StateFailed }

// transition moves from one of from to to; it fails once closing started.
func (s *Session) transition(to string, from ...string) bool {
	s.mu.Lock()
	ok := false
	for _, f := range from {
		if s.state == f {
			ok = true
		}
	}
	if !ok {
		s.mu.Unlock()
		return false
	}
	s.state = to
	s.stateVersion++
	if to == StateActive {
		s.activatedAt = time.Now()
	}
	ls := append([]func(string){}, s.listeners...)
	s.mu.Unlock()
	for _, l := range ls {
		l(to)
	}
	return true
}

// finish sets the final state exactly once.
func (s *Session) finish(state, reason string) bool {
	s.mu.Lock()
	if final(s.state) {
		s.mu.Unlock()
		return false
	}
	s.state = state
	s.stateVersion++
	s.endReason = reason
	s.endedAt = time.Now()
	ls := append([]func(string){}, s.listeners...)
	s.mu.Unlock()
	close(s.done)
	for _, l := range ls {
		l(state)
	}
	return true
}

// Manager tracks sessions.
type Manager struct {
	cfg    Config
	store  *authz.Store
	hub    Opener
	signer ca.Signer
	audit  *audit.Logger
	log    *slog.Logger

	mu       sync.Mutex
	sessions map[string]*Session
	idem     map[string]idemEntry
}

type idemEntry struct {
	bodyHash  string
	sessionID string
	expires   time.Time
}

// NewManager creates a Manager and subscribes it to policy changes.
func NewManager(cfg Config, store *authz.Store, hub Opener, signer ca.Signer, a *audit.Logger, log *slog.Logger) *Manager {
	cfg.defaults()
	m := &Manager{cfg: cfg, store: store, hub: hub, signer: signer, audit: a, log: log, sessions: map[string]*Session{}, idem: map[string]idemEntry{}}
	store.OnChange(m.onPolicyChange)
	return m
}

func newID(prefix string) string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// CreateRequest is the only accepted browser input for a new session.
type CreateRequest struct {
	HostID   string
	Login    string
	Rows     int
	Cols     int
	IdemKey  string
	BodyHash string
}

// Create validates and creates a session resource. It returns created=false
// when an identical idempotent request already produced a session.
func (m *Manager) Create(u authz.Subject, r CreateRequest) (*Session, bool, error) {
	if !authz.ValidID(r.HostID) || !authz.ValidLogin(r.Login) || r.Rows < 1 || r.Rows > 1000 || r.Cols < 1 || r.Cols > 1000 {
		return nil, false, ErrInvalid
	}
	idemKey := u.UserID + "\x00" + r.IdemKey
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked()
	if e, ok := m.idem[idemKey]; ok {
		if e.bodyHash != r.BodyHash {
			return nil, false, ErrConflict
		}
		if s := m.sessions[e.sessionID]; s != nil {
			return s, false, nil
		}
		return nil, false, ErrConflict
	}
	snap := m.store.Current()
	d := snap.Check(u, r.HostID, r.Login)
	if !d.Allowed {
		m.audit.Record(audit.Event{Actor: "user:" + u.UserID, Action: "session.create", Result: "denied", Target: r.HostID + "/" + r.Login, Revision: d.Revision, Reason: d.Reason})
		return nil, false, ErrForbidden
	}
	host, _ := snap.Host(r.HostID)
	if m.hub.Status(host) != "ready" {
		return nil, false, ErrUnavailable
	}
	perUser, total := 0, 0
	for _, s := range m.sessions {
		if final(s.State()) {
			continue
		}
		total++
		if s.Subject.UserID == u.UserID {
			perUser++
		}
	}
	if perUser >= m.cfg.MaxPerUser || total >= m.cfg.MaxTotal {
		return nil, false, ErrLimitReached
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &Session{ID: newID("s-"), Subject: u, HostID: r.HostID, Login: r.Login, CreatedAt: time.Now().UTC(),
		state: StateCreated, policyRevision: d.Revision, rows: r.Rows, cols: r.Cols, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	m.sessions[s.ID] = s
	m.idem[idemKey] = idemEntry{bodyHash: r.BodyHash, sessionID: s.ID, expires: time.Now().Add(24 * time.Hour)}
	m.audit.Record(audit.Event{Actor: "user:" + u.UserID, Action: "session.create", Result: "ok", Target: r.HostID + "/" + r.Login, SessionID: s.ID, Revision: d.Revision})
	time.AfterFunc(m.cfg.AttachTimeout, func() {
		s.mu.Lock()
		attached := s.attached
		s.mu.Unlock()
		if !attached {
			m.terminate(s, StateFailed, "attach_timeout")
		}
	})
	return s, true, nil
}

func (m *Manager) gcLocked() {
	now := time.Now()
	for k, e := range m.idem {
		if now.After(e.expires) {
			delete(m.idem, k)
		}
	}
	for id, s := range m.sessions {
		s.mu.Lock()
		old := final(s.state) && now.Sub(s.endedAt) > m.cfg.Retention
		s.mu.Unlock()
		if old {
			delete(m.sessions, id)
		}
	}
}

// Get returns a session visible to u (owner or admin).
func (m *Manager) Get(u authz.Subject, id string) (*Session, error) {
	m.mu.Lock()
	s := m.sessions[id]
	m.mu.Unlock()
	if s == nil || (s.Subject.UserID != u.UserID && !u.IsAdmin) {
		return nil, ErrNotFound
	}
	return s, nil
}

// List returns sessions visible to u.
func (m *Manager) List(u authz.Subject) []View {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []View
	for _, s := range m.sessions {
		if s.Subject.UserID == u.UserID || u.IsAdmin {
			out = append(out, s.View())
		}
	}
	return out
}

// Close idempotently closes a session on behalf of u.
func (m *Manager) Close(u authz.Subject, id, reason string) (*Session, error) {
	s, err := m.Get(u, id)
	if err != nil {
		return nil, err
	}
	actor := "user:" + u.UserID
	if s.Subject.UserID != u.UserID {
		reason = "admin_close"
	}
	m.audit.Record(audit.Event{Actor: actor, Action: "session.close", Result: "ok", SessionID: id, Reason: reason})
	m.terminate(s, StateClosed, reason)
	return s, nil
}

// terminate moves the session to closing then to its final state and tears
// down everything it holds. It is idempotent and only touches this session's
// stream, never the shared tunnel.
func (m *Manager) terminate(s *Session, state, reason string) {
	s.mu.Lock()
	if final(s.state) {
		s.mu.Unlock()
		return
	}
	if s.state != StateClosing {
		s.state = StateClosing
		s.stateVersion++
	}
	att := s.attempt
	ls := append([]func(string){}, s.listeners...)
	s.mu.Unlock()
	for _, l := range ls {
		l(StateClosing)
	}
	s.cancel(errors.New(reason))
	if att != nil && reason != "shell_exit" {
		m.hub.CloseAttempt(att.AgentID, att.Epoch, s.ID, att.ID, reason)
	}
	if s.finish(state, reason) {
		m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "session.end", Result: state, Target: s.HostID + "/" + s.Login, SessionID: s.ID, Reason: reason})
	}
}

func (m *Manager) onPolicyChange(snap *authz.Snapshot) {
	m.mu.Lock()
	var all []*Session
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	for _, s := range all {
		st := s.State()
		if final(st) || st == StateClosing {
			continue
		}
		if d := snap.Check(s.Subject, s.HostID, s.Login); d.Allowed {
			continue
		}
		if st == StateActive && !m.cfg.RevokeActive {
			continue
		}
		m.log.Info("closing session after access revocation", "session_id", s.ID)
		m.terminate(s, StateClosed, "permission_revoked")
	}
}

// Terminal is the browser side of a running session.
type Terminal interface {
	State(state string)
	Exit(reason string, status *int)
	Output(p []byte) error // blocks for backpressure
}

// Attach binds the single terminal consumer and runs the connection pipeline
// until the session ends. It returns ErrConflict if already attached.
func (m *Manager) Attach(s *Session, t Terminal) error {
	s.mu.Lock()
	if s.attached || s.state != StateCreated {
		s.mu.Unlock()
		return ErrConflict
	}
	s.attached = true
	s.listeners = append(s.listeners, t.State)
	s.mu.Unlock()
	t.State(StateCreated)
	reason, status := m.run(s, t)
	st := StateClosed
	if reason != "shell_exit" && reason != "user_close" && s.State() != StateActive && s.State() != StateClosing {
		st = StateFailed
	}
	m.terminate(s, st, reason)
	s.mu.Lock()
	reason = s.endReason
	s.mu.Unlock()
	t.Exit(reason, status)
	return nil
}

// failure maps an internal error to a stable, non-sensitive reason code.
func (m *Manager) failure(s *Session, phase string, err error) string {
	if cause := context.Cause(s.ctx); cause != nil {
		return cause.Error()
	}
	reason := phase + "_failed"
	switch {
	case errors.Is(err, agenthub.ErrNotReady):
		reason = "agent_unavailable"
	case errors.Is(err, agenthub.ErrBusy):
		reason = "too_many_streams"
	case errors.Is(err, sshgateway.ErrHostKeyMismatch):
		reason = "host_key_mismatch"
	}
	var rej *tunnel.RejectedError
	if errors.As(err, &rej) {
		reason = "agent_" + strings.ToLower(rej.Code)
	}
	m.log.Warn("session attempt failed", "session_id", s.ID, "phase", phase, "reason", reason, "err", err)
	return reason
}

func (m *Manager) recheck(s *Session, phase string) bool {
	d := m.store.Current().Check(s.Subject, s.HostID, s.Login)
	if !d.Allowed {
		m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "session." + phase, Result: "denied", SessionID: s.ID, Revision: d.Revision, Reason: d.Reason})
		return false
	}
	s.mu.Lock()
	s.policyRevision = d.Revision
	s.mu.Unlock()
	return true
}

func (m *Manager) run(s *Session, t Terminal) (string, *int) {
	ctx := s.ctx
	if m.cfg.MaxSessionDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, m.cfg.MaxSessionDuration, errors.New("max_session_duration"))
		defer cancel()
	}
	if !s.transition(StateWaitingAgent, StateCreated) {
		return "cancelled", nil
	}
	if !m.recheck(s, "open") {
		return "permission_denied", nil
	}
	attemptID := newID("a-")
	stream, err := m.hub.OpenStream(ctx, s.HostID, s.ID, attemptID)
	if err != nil {
		return m.failure(s, "agent_open", err), nil
	}
	defer stream.Close()
	att := &Attempt{ID: attemptID, AgentID: stream.AgentID, Epoch: stream.Epoch, DataTunnelID: stream.TunnelID, StreamID: stream.StreamID}
	s.mu.Lock()
	s.attempt = att
	s.mu.Unlock()
	stopOnCancel := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stopOnCancel()

	// Sign only after the Agent acknowledged a live TCP connection to sshd.
	if !s.transition(StateSigning, StateWaitingAgent) {
		return "cancelled", nil
	}
	if !m.recheck(s, "sign") {
		return "permission_denied", nil
	}
	snap := m.store.Current()
	host, ok := snap.Host(s.HostID)
	if !ok {
		return "permission_denied", nil
	}
	key, err := sshgateway.NewEphemeralKey()
	if err != nil {
		return m.failure(s, "keygen", err), nil
	}
	req := ca.Request{PublicKey: key.PublicKey(), KeyID: "user:" + s.Subject.UserID + "/session:" + s.ID, Principal: authz.Principal(snap.Scope, s.HostID, s.Login)}
	cert, err := m.signer.SignUserCert(ctx, req)
	if err != nil {
		m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "ca.sign", Result: "error", SessionID: s.ID, AttemptID: attemptID})
		return m.failure(s, "ca_sign", err), nil
	}
	s.mu.Lock()
	att.CertSerial = cert.Serial
	att.CertKeyID = cert.KeyId
	att.PublicKeyFingerprint = sshgateway.Fingerprint(key.PublicKey())
	att.ValidAfter = time.Unix(int64(cert.ValidAfter), 0).UTC()
	att.ValidBefore = time.Unix(int64(cert.ValidBefore), 0).UTC()
	s.mu.Unlock()
	m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "ca.sign", Result: "ok", SessionID: s.ID, AttemptID: attemptID,
		Extra: map[string]any{"serial": fmt.Sprint(cert.Serial), "key_id": cert.KeyId, "valid_after": att.ValidAfter, "valid_before": att.ValidBefore, "fingerprint": att.PublicKeyFingerprint, "epoch": att.Epoch, "stream_id": att.StreamID}})

	if !s.transition(StateSSHAuthenticating, StateSigning) {
		return "cancelled", nil
	}
	client, err := sshgateway.Connect(ctx, stream, sshgateway.Target{HostID: s.HostID, Login: s.Login, HostKeys: host.HostKeys()}, key, cert, m.cfg.SSHHandshake)
	if err != nil {
		if errors.Is(err, sshgateway.ErrHostKeyMismatch) || strings.Contains(err.Error(), sshgateway.ErrHostKeyMismatch.Error()) {
			m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "ssh.host_key", Result: "mismatch", Target: s.HostID, SessionID: s.ID})
			return "host_key_mismatch", nil
		}
		return m.failure(s, "ssh_auth", err), nil
	}
	defer client.Close()
	stopClient := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopClient()

	s.mu.Lock()
	rows, cols := s.rows, s.cols
	s.mu.Unlock()
	sess, err := sshgateway.Shell(client, rows, cols)
	if err != nil {
		return m.failure(s, "pty", err), nil
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return m.failure(s, "pty", err), nil
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return m.failure(s, "pty", err), nil
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return m.failure(s, "pty", err), nil
	}
	// Last authorization gate: nothing runs on the host before this passes.
	if ctx.Err() != nil {
		return m.failure(s, "activate", ctx.Err()), nil
	}
	if !m.recheck(s, "activate") {
		return "permission_denied", nil
	}
	if err := sess.Shell(); err != nil {
		return m.failure(s, "shell", err), nil
	}
	s.mu.Lock()
	s.sshSession = sess
	s.stdin = stdin
	s.mu.Unlock()
	if !s.transition(StateActive, StateSSHAuthenticating) {
		return "cancelled", nil
	}
	m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "session.active", Result: "ok", Target: s.HostID + "/" + s.Login, SessionID: s.ID, AttemptID: attemptID})

	var outWG sync.WaitGroup
	pump := func(r io.Reader) {
		defer outWG.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if t.Output(buf[:n]) != nil {
					s.cancel(errors.New("browser_disconnected"))
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	outWG.Add(2)
	go pump(stdout)
	go pump(stderr)
	waitErr := sess.Wait()
	outWG.Wait()
	if cause := context.Cause(ctx); cause != nil {
		return cause.Error(), nil
	}
	var exitErr *ssh.ExitError
	switch {
	case waitErr == nil:
		zero := 0
		return "shell_exit", &zero
	case errors.As(waitErr, &exitErr):
		st := exitErr.ExitStatus()
		return "shell_exit", &st
	default:
		return m.failure(s, "transport", waitErr), nil
	}
}

// Input forwards terminal bytes; input before active is dropped.
func (s *Session) Input(p []byte) error {
	s.mu.Lock()
	w := s.stdin
	active := s.state == StateActive
	s.mu.Unlock()
	if !active || w == nil {
		return nil
	}
	_, err := w.Write(p)
	return err
}

// Resize applies a window change (or records it for the initial PTY).
func (s *Session) Resize(rows, cols int) error {
	s.mu.Lock()
	s.rows, s.cols = rows, cols
	sess := s.sshSession
	s.mu.Unlock()
	if sess == nil {
		return nil
	}
	return sess.WindowChange(rows, cols)
}

// BodyHash hashes a canonical request body for idempotency.
func BodyHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
