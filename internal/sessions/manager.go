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
	IdleTimeout        time.Duration // 0 = disabled
	MaxPerUser         int
	MaxTotal           int
	MaxConcurrentSigns int  // bounds concurrent CA sign requests
	RevokeActive       bool // close active sessions when access is revoked
	Retention          time.Duration
}

const (
	maxIdemEntries = 50000
	maxSeenKeys    = 100000
)

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
	if c.MaxConcurrentSigns <= 0 {
		c.MaxConcurrentSigns = 16
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

// Session is one Web or native SSH session resource.
type Session struct {
	ID        string
	Subject   authz.Subject
	HostID    string
	Login     string
	CreatedAt time.Time
	Mode      string // ModeWeb or ModeNative

	clientKey      ssh.PublicKey // native only: the CLI's ephemeral public key
	onFinish       func()
	finishOnce     sync.Once
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
	idleMu         sync.Mutex
	idleTimer      *time.Timer
	idleTimeout    time.Duration
	listeners      []func(state string)
	done           chan struct{}
}

func (s *Session) startIdle(d time.Duration) func() {
	if d <= 0 {
		return func() {}
	}
	s.idleMu.Lock()
	s.idleTimeout = d
	s.idleTimer = time.AfterFunc(d, func() {
		s.cancel(errors.New("idle_timeout"))
	})
	s.idleMu.Unlock()
	return func() {
		s.idleMu.Lock()
		if s.idleTimer != nil {
			s.idleTimer.Stop()
			s.idleTimer = nil
		}
		s.idleMu.Unlock()
	}
}

func (s *Session) touchIdle() {
	s.idleMu.Lock()
	if s.idleTimer != nil && s.idleTimeout > 0 {
		s.idleTimer.Reset(s.idleTimeout)
	}
	s.idleMu.Unlock()
}

// View is the public projection of a session.
type View struct {
	ID         string    `json:"id"`
	HostID     string    `json:"host_id"`
	LoginUser  string    `json:"login_user"`
	Mode       string    `json:"mode"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	TermPath   string    `json:"terminal_path,omitempty"`
	TunnelPath string    `json:"tunnel_path,omitempty"`
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
	v := View{ID: s.ID, HostID: s.HostID, LoginUser: s.Login, Mode: s.Mode, State: s.state, CreatedAt: s.CreatedAt,
		UserID: s.Subject.UserID, Version: s.stateVersion, ActivateAt: s.activatedAt}
	if s.Mode == ModeNative {
		v.TunnelPath = "/api/v1/ssh-sessions/" + s.ID + "/tunnel"
	} else {
		v.TermPath = "/api/v1/ssh-sessions/" + s.ID + "/terminal"
	}
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
	if s.onFinish != nil {
		s.finishOnce.Do(s.onFinish)
	}
	close(s.done)
	for _, l := range ls {
		l(state)
	}
	return true
}

// Manager tracks sessions with O(1) active quota accounting and background GC.
type Manager struct {
	cfg     Config
	store   *authz.Store
	hub     Opener
	signer  ca.Signer
	signSem chan struct{}
	audit   *audit.Logger
	log     *slog.Logger

	mu            sync.Mutex
	sessions      map[string]*Session
	activeTotal   int
	activePerUser map[string]int
	idem          map[string]idemEntry
	idemOrder     []string
	seenKeys      map[string]time.Time // native client key fingerprints (one key per attempt)
	seenKeyOrder  []string

	stopGC   chan struct{}
	gcDone   chan struct{}
	stopOnce sync.Once
}

type idemEntry struct {
	bodyHash  string
	sessionID string
	expires   time.Time
}

// NewManager creates a Manager, starts its periodic GC loop and subscribes it
// to policy changes.
func NewManager(cfg Config, store *authz.Store, hub Opener, signer ca.Signer, a *audit.Logger, log *slog.Logger) *Manager {
	cfg.defaults()
	m := &Manager{
		cfg:           cfg,
		store:         store,
		hub:           hub,
		signer:        signer,
		signSem:       make(chan struct{}, cfg.MaxConcurrentSigns),
		audit:         a,
		log:           log,
		sessions:      map[string]*Session{},
		activePerUser: map[string]int{},
		idem:          map[string]idemEntry{},
		seenKeys:      map[string]time.Time{},
		stopGC:        make(chan struct{}),
		gcDone:        make(chan struct{}),
	}
	store.OnChange(m.onPolicyChange)
	go m.gcLoop()
	return m
}

// Shutdown stops the background GC loop.
func (m *Manager) Shutdown() {
	m.stopOnce.Do(func() { close(m.stopGC) })
	<-m.gcDone
}

func (m *Manager) gcLoop() {
	defer close(m.gcDone)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stopGC:
			return
		case <-t.C:
			m.gcExpired()
		}
	}
}

func (m *Manager) gcExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.idem {
		if now.After(e.expires) {
			delete(m.idem, k)
		}
	}
	m.compactIdemOrderLocked()
	for fp, t := range m.seenKeys {
		if now.Sub(t) > keyReuseWindow {
			delete(m.seenKeys, fp)
		}
	}
	m.compactSeenKeyOrderLocked()
	for id, s := range m.sessions {
		s.mu.Lock()
		old := final(s.state) && now.Sub(s.endedAt) > m.cfg.Retention
		s.mu.Unlock()
		if old {
			delete(m.sessions, id)
		}
	}
}

func (m *Manager) compactIdemOrderLocked() {
	if len(m.idemOrder) <= len(m.idem)*2 {
		return
	}
	kept := m.idemOrder[:0]
	for _, k := range m.idemOrder {
		if _, ok := m.idem[k]; ok {
			kept = append(kept, k)
		}
	}
	m.idemOrder = kept
}

func (m *Manager) compactSeenKeyOrderLocked() {
	if len(m.seenKeyOrder) <= len(m.seenKeys)*2 {
		return
	}
	kept := m.seenKeyOrder[:0]
	for _, fp := range m.seenKeyOrder {
		if _, ok := m.seenKeys[fp]; ok {
			kept = append(kept, fp)
		}
	}
	m.seenKeyOrder = kept
}

func (m *Manager) evictIdemIfFullLocked() {
	for len(m.idem) >= maxIdemEntries && len(m.idemOrder) > 0 {
		oldest := m.idemOrder[0]
		m.idemOrder = m.idemOrder[1:]
		delete(m.idem, oldest)
	}
}

func (m *Manager) evictSeenKeyIfFullLocked() {
	for len(m.seenKeys) >= maxSeenKeys && len(m.seenKeyOrder) > 0 {
		oldest := m.seenKeyOrder[0]
		m.seenKeyOrder = m.seenKeyOrder[1:]
		delete(m.seenKeys, oldest)
	}
}

func (m *Manager) signCert(ctx context.Context, req ca.Request) (*ssh.Certificate, error) {
	select {
	case m.signSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-m.signSem }()
	return m.signer.SignUserCert(ctx, req)
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

// precheckAdmit evaluates policy and agent readiness OUTSIDE m.mu so disk/hub
// calls never contend with the session map lock.
func (m *Manager) precheckAdmit(u authz.Subject, hostID, login, mode string) (authz.Decision, error) {
	snap := m.store.Current()
	d := snap.Check(u, hostID, login)
	if !d.Allowed {
		m.audit.Record(audit.Event{Actor: "user:" + u.UserID, User: u.Name, Action: "session.create", Result: "denied", Target: hostID + "/" + login, Revision: d.Revision, Reason: d.Reason, Extra: map[string]any{"mode": mode}})
		return d, ErrForbidden
	}
	host, _ := snap.Host(hostID)
	if m.hub.Status(host) != "ready" {
		return d, ErrUnavailable
	}
	return d, nil
}

// Create validates and creates a session resource. It returns created=false
// when an identical idempotent request already produced a session.
func (m *Manager) Create(u authz.Subject, r CreateRequest) (*Session, bool, error) {
	if !authz.ValidID(r.HostID) || !authz.ValidLogin(r.Login) || r.Rows < 1 || r.Rows > 1000 || r.Cols < 1 || r.Cols > 1000 {
		return nil, false, ErrInvalid
	}
	idemKey := u.UserID + "\x00" + r.IdemKey
	now := time.Now()

	// Fast idempotency check before checking host readiness.
	m.mu.Lock()
	if e, ok := m.idem[idemKey]; ok {
		if now.After(e.expires) {
			delete(m.idem, idemKey)
		} else {
			if e.bodyHash != r.BodyHash {
				m.mu.Unlock()
				return nil, false, ErrConflict
			}
			if s := m.sessions[e.sessionID]; s != nil {
				m.mu.Unlock()
				return s, false, nil
			}
			m.mu.Unlock()
			return nil, false, ErrConflict
		}
	}
	m.mu.Unlock()

	d, err := m.precheckAdmit(u, r.HostID, r.Login, ModeWeb)
	if err != nil {
		return nil, false, err
	}

	m.mu.Lock()
	if e, ok := m.idem[idemKey]; ok && !now.After(e.expires) {
		if e.bodyHash != r.BodyHash {
			m.mu.Unlock()
			return nil, false, ErrConflict
		}
		if s := m.sessions[e.sessionID]; s != nil {
			m.mu.Unlock()
			return s, false, nil
		}
		m.mu.Unlock()
		return nil, false, ErrConflict
	}
	s, err := m.registerLocked(u, r.HostID, r.Login, ModeWeb, d.Revision)
	if err != nil {
		m.mu.Unlock()
		return nil, false, err
	}
	s.rows, s.cols = r.Rows, r.Cols
	m.evictIdemIfFullLocked()
	m.idem[idemKey] = idemEntry{bodyHash: r.BodyHash, sessionID: s.ID, expires: now.Add(24 * time.Hour)}
	m.idemOrder = append(m.idemOrder, idemKey)
	m.mu.Unlock()

	m.postRegister(s, d.Revision)
	return s, true, nil
}

// registerLocked enforces O(1) active session quotas and inserts s into
// m.sessions. m.mu must be held; no I/O or cross-subsystem locks are taken.
func (m *Manager) registerLocked(u authz.Subject, hostID, login, mode string, rev uint64) (*Session, error) {
	if m.activePerUser[u.UserID] >= m.cfg.MaxPerUser || m.activeTotal >= m.cfg.MaxTotal {
		return nil, ErrLimitReached
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	uid := u.UserID
	s := &Session{
		ID:             newID("s-"),
		Subject:        u,
		HostID:         hostID,
		Login:          login,
		CreatedAt:      time.Now().UTC(),
		Mode:           mode,
		state:          StateCreated,
		policyRevision: rev,
		ctx:            ctx,
		cancel:         cancel,
		done:           make(chan struct{}),
		onFinish: func() {
			m.mu.Lock()
			if m.activeTotal > 0 {
				m.activeTotal--
			}
			if n := m.activePerUser[uid]; n <= 1 {
				delete(m.activePerUser, uid)
			} else {
				m.activePerUser[uid] = n - 1
			}
			m.mu.Unlock()
		},
	}
	m.sessions[s.ID] = s
	m.activeTotal++
	m.activePerUser[uid]++
	return s, nil
}

func (m *Manager) postRegister(s *Session, rev uint64) {
	m.audit.Record(audit.Event{
		Actor:     "user:" + s.Subject.UserID,
		User:      s.Subject.Name,
		Action:    "session.create",
		Result:    "ok",
		Target:    s.HostID + "/" + s.Login,
		SessionID: s.ID,
		Revision:  rev,
		Extra:     map[string]any{"mode": s.Mode},
	})
	time.AfterFunc(m.cfg.AttachTimeout, func() {
		s.mu.Lock()
		attached := s.attached
		s.mu.Unlock()
		if !attached {
			m.terminate(s, StateFailed, "attach_timeout")
		}
	})
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
	var targets []*Session
	for _, s := range m.sessions {
		if s.Subject.UserID == u.UserID || u.IsAdmin {
			targets = append(targets, s)
		}
	}
	m.mu.Unlock()
	out := make([]View, 0, len(targets))
	for _, s := range targets {
		out = append(out, s.View())
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

// CloseUserSessions terminates every non-final session belonging to userID.
// Used when an administrator revokes a user's access centrally.
func (m *Manager) CloseUserSessions(userID, actorID, reason string) int {
	m.mu.Lock()
	var targets []*Session
	for _, s := range m.sessions {
		if s.Subject.UserID == userID {
			targets = append(targets, s)
		}
	}
	m.mu.Unlock()
	closed := 0
	for _, s := range targets {
		st := s.State()
		if final(st) || st == StateClosing {
			continue
		}
		m.audit.Record(audit.Event{Actor: actorID, Action: "session.close", Result: "ok", Target: s.HostID + "/" + s.Login, SessionID: s.ID, Reason: reason})
		m.terminate(s, StateClosed, reason)
		closed++
	}
	return closed
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
		m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, User: s.Subject.Name, Action: "session.end", Result: state, Target: s.HostID + "/" + s.Login, SessionID: s.ID, Reason: reason})
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
	if s.Mode != ModeWeb {
		return ErrConflict
	}
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

func (m *Manager) recheck(s *Session, phase string) (*authz.Snapshot, *authz.Host, bool) {
	snap := m.store.Current()
	d := snap.Check(s.Subject, s.HostID, s.Login)
	if !d.Allowed {
		m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, User: s.Subject.Name, Action: "session." + phase, Result: "denied", SessionID: s.ID, Revision: d.Revision, Reason: d.Reason})
		return nil, nil, false
	}
	host, ok := snap.Host(s.HostID)
	if !ok {
		return nil, nil, false
	}
	s.mu.Lock()
	s.policyRevision = d.Revision
	s.mu.Unlock()
	return snap, host, true
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
	if _, _, ok := m.recheck(s, "open"); !ok {
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
	snap, host, ok := m.recheck(s, "sign")
	if !ok {
		return "permission_denied", nil
	}
	key, err := sshgateway.NewEphemeralKey()
	if err != nil {
		return m.failure(s, "keygen", err), nil
	}
	req := ca.Request{PublicKey: key.PublicKey(), KeyID: "user:" + s.Subject.UserID + "/session:" + s.ID, Principal: authz.Principal(snap.Scope, s.HostID, s.Login)}
	cert, err := m.signCert(ctx, req)
	if err != nil {
		m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, User: s.Subject.Name, Action: "ca.sign", Result: "error", SessionID: s.ID, AttemptID: attemptID})
		return m.failure(s, "ca_sign", err), nil
	}
	s.mu.Lock()
	att.CertSerial = cert.Serial
	att.CertKeyID = cert.KeyId
	att.PublicKeyFingerprint = sshgateway.Fingerprint(key.PublicKey())
	att.ValidAfter = time.Unix(int64(cert.ValidAfter), 0).UTC()
	att.ValidBefore = time.Unix(int64(cert.ValidBefore), 0).UTC()
	s.mu.Unlock()
	m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, User: s.Subject.Name, Action: "ca.sign", Result: "ok", SessionID: s.ID, AttemptID: attemptID,
		Extra: map[string]any{"serial": fmt.Sprint(cert.Serial), "key_id": cert.KeyId, "valid_after": att.ValidAfter, "valid_before": att.ValidBefore, "fingerprint": att.PublicKeyFingerprint, "epoch": att.Epoch, "stream_id": att.StreamID}})

	if !s.transition(StateSSHAuthenticating, StateSigning) {
		return "cancelled", nil
	}
	client, err := sshgateway.Connect(ctx, stream, sshgateway.Target{
		HostID:             s.HostID,
		Login:              s.Login,
		HostKeys:           host.HostKeys(),
		HostCAs:            snap.HostCAs(),
		HostCertPrincipals: host.CertPrincipals(),
	}, key, cert, m.cfg.SSHHandshake)
	if err != nil {
		if errors.Is(err, sshgateway.ErrHostKeyMismatch) || strings.Contains(err.Error(), sshgateway.ErrHostKeyMismatch.Error()) {
			m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, User: s.Subject.Name, Action: "ssh.host_key", Result: "mismatch", Target: s.HostID, SessionID: s.ID})
			return "host_key_mismatch", nil
		}
		return m.failure(s, "ssh_auth", err), nil
	}
	stream.MarkAuthenticated()
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
	if _, _, ok := m.recheck(s, "activate"); !ok {
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
	stopIdle := s.startIdle(m.cfg.IdleTimeout)
	defer stopIdle()
	m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, User: s.Subject.Name, Action: "session.active", Result: "ok", Target: s.HostID + "/" + s.Login, SessionID: s.ID, AttemptID: attemptID})

	var outWG sync.WaitGroup
	pump := func(r io.Reader) {
		defer outWG.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				s.touchIdle()
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
	s.touchIdle()
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

// BodyHash hashes canonical request fields for idempotency checks.
func BodyHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
