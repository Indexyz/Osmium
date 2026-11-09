package sessions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/sshgateway"
)

// Session modes.
const (
	// ModeWeb: the Server is the SSH client and the browser gets a terminal.
	ModeWeb = "web"
	// ModeNative: the user's own OpenSSH client speaks SSH end to end; the
	// Server authorizes, has the CLI's ephemeral key signed and relays bytes.
	ModeNative = "native"
)

// ErrKeyReused is returned when a native client offers a public key that was
// already used for another attempt.
var ErrKeyReused = errors.New("public key already used")

// keyReuseWindow is how long native client key fingerprints are remembered.
// It is far longer than any certificate lifetime.
const keyReuseWindow = 24 * time.Hour

// NativeRequest is the only accepted input for a native session. The CLI
// supplies its ephemeral public key; principal, TTL and CA options are
// decided by the Server.
type NativeRequest struct {
	HostID    string
	Login     string
	PublicKey string // authorized_keys format
}

// ParseClientKey accepts a plain (non-certificate) Ed25519 or ECDSA key.
func ParseClientKey(s string) (ssh.PublicKey, error) {
	if len(s) > 1024 {
		return nil, ErrInvalid
	}
	k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, ErrInvalid
	}
	switch k.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return k, nil
	}
	return nil, ErrInvalid
}

// CreateNative authorizes and creates a native session for u.
func (m *Manager) CreateNative(u authz.Subject, r NativeRequest) (*Session, error) {
	if !authz.ValidID(r.HostID) || !authz.ValidLogin(r.Login) {
		return nil, ErrInvalid
	}
	key, err := ParseClientKey(r.PublicKey)
	if err != nil {
		return nil, err
	}
	fp := sshgateway.Fingerprint(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked()
	if _, seen := m.seenKeys[fp]; seen {
		m.audit.Record(audit.Event{Actor: "user:" + u.UserID, Action: "session.create", Result: "denied", Target: r.HostID + "/" + r.Login, Reason: "key_reused", Extra: map[string]any{"mode": ModeNative, "fingerprint": fp}})
		return nil, ErrKeyReused
	}
	s, err := m.admitLocked(u, r.HostID, r.Login, ModeNative)
	if err != nil {
		return nil, err
	}
	m.seenKeys[fp] = time.Now()
	s.clientKey = key
	return s, nil
}

// NativeClient is the CLI side of a native session.
type NativeClient interface {
	State(state string)
	// Ready hands the certificate and pinned host keys to the CLI; after it
	// returns, Read/Write carry raw SSH bytes.
	Ready(cert *ssh.Certificate, hostKeys []ssh.PublicKey) error
	io.ReadWriter
}

// AttachNative runs a native session until it ends. It returns ErrConflict if
// the session is not a fresh native session.
func (m *Manager) AttachNative(s *Session, c NativeClient) error {
	if s.Mode != ModeNative {
		return ErrConflict
	}
	s.mu.Lock()
	if s.attached || s.state != StateCreated {
		s.mu.Unlock()
		return ErrConflict
	}
	s.attached = true
	s.listeners = append(s.listeners, c.State)
	s.mu.Unlock()
	c.State(StateCreated)
	reason := m.runNative(s, c)
	st := StateClosed
	if s.State() != StateActive && s.State() != StateClosing {
		st = StateFailed
	}
	m.terminate(s, st, reason)
	return nil
}

func (m *Manager) runNative(s *Session, c NativeClient) string {
	ctx := s.ctx
	if m.cfg.MaxSessionDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, m.cfg.MaxSessionDuration, errors.New("max_session_duration"))
		defer cancel()
	}
	if !s.transition(StateWaitingAgent, StateCreated) {
		return "cancelled"
	}
	if !m.recheck(s, "open") {
		return "permission_denied"
	}
	attemptID := newID("a-")
	stream, err := m.hub.OpenStream(ctx, s.HostID, s.ID, attemptID)
	if err != nil {
		return m.failure(s, "agent_open", err)
	}
	defer stream.Close()
	att := &Attempt{ID: attemptID, AgentID: stream.AgentID, Epoch: stream.Epoch, DataTunnelID: stream.TunnelID, StreamID: stream.StreamID}
	s.mu.Lock()
	s.attempt = att
	s.mu.Unlock()
	stopOnCancel := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stopOnCancel()

	// As in Web mode, sign only after the Agent acknowledged sshd.
	if !s.transition(StateSigning, StateWaitingAgent) {
		return "cancelled"
	}
	if !m.recheck(s, "sign") {
		return "permission_denied"
	}
	snap := m.store.Current()
	host, ok := snap.Host(s.HostID)
	if !ok {
		return "permission_denied"
	}
	req := ca.Request{PublicKey: s.clientKey, KeyID: "user:" + s.Subject.UserID + "/session:" + s.ID, Principal: authz.Principal(snap.Scope, s.HostID, s.Login)}
	cert, err := m.signer.SignUserCert(ctx, req)
	if err != nil {
		m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "ca.sign", Result: "error", SessionID: s.ID, AttemptID: attemptID})
		return m.failure(s, "ca_sign", err)
	}
	s.mu.Lock()
	att.CertSerial = cert.Serial
	att.CertKeyID = cert.KeyId
	att.PublicKeyFingerprint = sshgateway.Fingerprint(s.clientKey)
	att.ValidAfter = time.Unix(int64(cert.ValidAfter), 0).UTC()
	att.ValidBefore = time.Unix(int64(cert.ValidBefore), 0).UTC()
	s.mu.Unlock()
	m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "ca.sign", Result: "ok", SessionID: s.ID, AttemptID: attemptID,
		Extra: map[string]any{"mode": ModeNative, "serial": fmt.Sprint(cert.Serial), "key_id": cert.KeyId, "valid_after": att.ValidAfter, "valid_before": att.ValidBefore, "fingerprint": att.PublicKeyFingerprint, "epoch": att.Epoch, "stream_id": att.StreamID}})

	// The Server cannot observe SSH authentication in this mode; the last
	// gate is before any byte of the user's SSH connection reaches sshd.
	if ctx.Err() != nil {
		return m.failure(s, "activate", ctx.Err())
	}
	if !m.recheck(s, "activate") {
		return "permission_denied"
	}
	if !s.transition(StateActive, StateSigning) {
		return "cancelled"
	}
	if err := c.Ready(cert, host.HostKeys()); err != nil {
		return "client_disconnected"
	}
	m.audit.Record(audit.Event{Actor: "user:" + s.Subject.UserID, Action: "session.active", Result: "ok", Target: s.HostID + "/" + s.Login, SessionID: s.ID, AttemptID: attemptID, Extra: map[string]any{"mode": ModeNative}})

	type result struct{ client bool }
	done := make(chan result, 2)
	go func() {
		_, _ = io.CopyBuffer(stream, c, make([]byte, 32*1024))
		done <- result{client: true}
	}()
	go func() {
		_, _ = io.CopyBuffer(c, stream, make([]byte, 32*1024))
		done <- result{client: false}
	}()
	first := <-done
	// Unblock the stream side; the caller closes the client side.
	_ = stream.Close()
	if cause := context.Cause(ctx); cause != nil {
		return cause.Error()
	}
	if first.client {
		return "client_closed"
	}
	return "remote_closed"
}
