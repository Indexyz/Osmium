// Package agenthub manages Agent presence on the Server: the control WSS
// (hello/welcome/heartbeat), connection epochs, one-time data tunnel tickets,
// the shared smux data tunnel per epoch and the per-host stream quota.
package agenthub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/tunnel"
)

// Errors returned by OpenStream.
var (
	ErrNotReady = errors.New("host agent is not ready")
	ErrBusy     = errors.New("host stream quota exhausted")
)

// Config tunes the hub.
type Config struct {
	ServerID         string
	Mux              tunnel.MuxConfig
	TicketTTL        time.Duration
	HelloTimeout     time.Duration
	HeartbeatTimeout time.Duration
	StreamOpen       time.Duration
	MaxStreams       int // per Agent epoch, pending + active
}

func (c *Config) defaults() {
	if c.ServerID == "" {
		c.ServerID = "server-1"
	}
	if c.Mux == (tunnel.MuxConfig{}) {
		c.Mux = tunnel.DefaultMuxConfig()
	}
	if c.TicketTTL <= 0 {
		c.TicketTTL = 30 * time.Second
	}
	if c.HelloTimeout <= 0 {
		c.HelloTimeout = 10 * time.Second
	}
	if c.HeartbeatTimeout <= 0 {
		c.HeartbeatTimeout = 45 * time.Second
	}
	if c.StreamOpen <= 0 {
		c.StreamOpen = 10 * time.Second
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 32
	}
}

// Hub is the Agent manager.
type Hub struct {
	cfg   Config
	store *authz.Store
	audit *audit.Logger
	log   *slog.Logger

	mu       sync.Mutex
	epoch    uint64
	byAgent  map[string]*presence
	tickets  map[string]*ticket // sha256(ticket) hex → binding
	onChange []func(hostID string)
}

type ticket struct {
	agentID, hostID, ownerID, tunnelID string
	epoch                              uint64
	expires                            time.Time
}

type presence struct {
	agentID, hostID, cn string
	epoch               uint64
	tunnelID            string
	ctx                 context.Context
	cancel              context.CancelFunc
	control             *websocket.Conn
	writeMu             sync.Mutex
	mux                 *smux.Session
	sem                 chan struct{}
	agentVersion        string
	reportedLabels      map[string]string
	connectedAt         time.Time
}

// New creates a hub and subscribes it to policy changes.
func New(cfg Config, store *authz.Store, a *audit.Logger, log *slog.Logger) *Hub {
	cfg.defaults()
	h := &Hub{cfg: cfg, store: store, audit: a, log: log, byAgent: map[string]*presence{}, tickets: map[string]*ticket{}}
	store.OnChange(h.reconcilePolicy)
	return h
}

// OnStatusChange registers a callback fired when a host's status changes.
func (h *Hub) OnStatusChange(f func(hostID string)) {
	h.mu.Lock()
	h.onChange = append(h.onChange, f)
	h.mu.Unlock()
}

func (h *Hub) notify(hostID string) {
	h.mu.Lock()
	fs := append([]func(string){}, h.onChange...)
	h.mu.Unlock()
	for _, f := range fs {
		f(hostID)
	}
}

// reconcilePolicy ends epochs whose host was removed, disabled or rebound.
func (h *Hub) reconcilePolicy(s *authz.Snapshot) {
	h.mu.Lock()
	var stale []*presence
	for _, p := range h.byAgent {
		host, ok := s.HostByAgentCN(p.cn)
		if !ok || host.ID != p.hostID || host.Agent.ID != p.agentID || host.Disabled {
			stale = append(stale, p)
		}
	}
	h.mu.Unlock()
	for _, p := range stale {
		h.log.Info("closing agent epoch after policy change", "agent_id", p.agentID, "epoch", p.epoch)
		p.cancel()
	}
}

// Status returns the host status for the directory.
func (h *Hub) Status(host *authz.Host) string {
	if host.Disabled {
		return "disabled"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.byAgent[host.Agent.ID]
	switch {
	case p == nil || p.hostID != host.ID:
		return "offline"
	case p.mux == nil || p.mux.IsClosed():
		return "connecting"
	default:
		return "ready"
	}
}

// agentIdentity maps the verified client certificate to the inventory entry.
func (h *Hub) agentIdentity(r *http.Request) (*authz.Host, string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil, "", errors.New("no verified client certificate")
	}
	cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
	host, ok := h.store.Current().HostByAgentCN(cn)
	if !ok {
		return nil, cn, errors.New("unknown agent identity")
	}
	if host.Disabled {
		return nil, cn, errors.New("host disabled")
	}
	return host, cn, nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func digest(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func (p *presence) send(ctx context.Context, typ string, payload any) error {
	b, err := protocol.Encode(typ, payload)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.control.Write(ctx, websocket.MessageText, b)
}

// HandleControl serves /agent/v1/control on the mTLS listener.
func (h *Hub) HandleControl(w http.ResponseWriter, r *http.Request) {
	host, cn, err := h.agentIdentity(r)
	if err != nil {
		h.audit.Record(audit.Event{Actor: "agent:" + cn, Action: "agent.register", Result: "denied", Reason: err.Error()})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.SubprotocolControl}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	if ws.Subprotocol() != protocol.SubprotocolControl {
		ws.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}
	ws.SetReadLimit(protocol.MaxControlMessage)
	helloCtx, cancelHello := context.WithTimeout(r.Context(), h.cfg.HelloTimeout)
	typ, data, err := ws.Read(helloCtx)
	cancelHello()
	if err != nil || typ != websocket.MessageText {
		ws.Close(websocket.StatusPolicyViolation, "hello required")
		return
	}
	mt, payload, err := protocol.Decode(data)
	if err != nil || mt != protocol.TypeHello {
		ws.Close(websocket.StatusPolicyViolation, "invalid hello")
		return
	}
	hello := payload.(*protocol.Hello)

	ctx, cancel := context.WithCancel(context.Background())
	p := &presence{
		agentID: host.Agent.ID, hostID: host.ID, cn: cn,
		tunnelID: "dt-" + randomToken(9), ctx: ctx, cancel: cancel, control: ws,
		sem: make(chan struct{}, h.cfg.MaxStreams), agentVersion: hello.AgentVersion,
		reportedLabels: hello.ReportedLabels, connectedAt: time.Now(),
	}
	tk := randomToken(32)
	h.mu.Lock()
	h.epoch++
	p.epoch = h.epoch
	old := h.byAgent[p.agentID]
	h.byAgent[p.agentID] = p
	h.tickets[digest(tk)] = &ticket{agentID: p.agentID, hostID: p.hostID, ownerID: h.cfg.ServerID, tunnelID: p.tunnelID, epoch: p.epoch, expires: time.Now().Add(h.cfg.TicketTTL)}
	h.gcTicketsLocked()
	h.mu.Unlock()
	if old != nil {
		old.cancel() // a newer registration supersedes the old epoch
	}
	h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.register", Result: "ok", Target: p.hostID, Extra: map[string]any{"epoch": p.epoch, "agent_version": p.agentVersion}})
	defer func() {
		cancel()
		h.mu.Lock()
		if h.byAgent[p.agentID] == p {
			delete(h.byAgent, p.agentID)
		}
		h.mu.Unlock()
		h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.disconnect", Result: "ok", Target: p.hostID, Extra: map[string]any{"epoch": p.epoch}})
		h.notify(p.hostID)
	}()
	go func() {
		<-ctx.Done()
		ws.Close(websocket.StatusGoingAway, "epoch ended")
		h.mu.Lock()
		mux := p.mux
		h.mu.Unlock()
		if mux != nil {
			_ = mux.Close()
		}
	}()
	welcome := protocol.Welcome{AgentID: p.agentID, HostID: p.hostID, Epoch: p.epoch, DataTunnelID: p.tunnelID, DataPath: protocol.DataPath, DataTicket: tk, ExpiresAt: time.Now().Add(h.cfg.TicketTTL).UTC(), SmuxVersion: 2}
	if err := p.send(ctx, protocol.TypeWelcome, welcome); err != nil {
		return
	}
	h.notify(p.hostID)
	for {
		rctx, rcancel := context.WithTimeout(ctx, h.cfg.HeartbeatTimeout)
		typ, data, err := ws.Read(rctx)
		rcancel()
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			ws.Close(websocket.StatusUnsupportedData, "text only")
			return
		}
		mt, payload, err := protocol.Decode(data)
		if err != nil {
			ws.Close(websocket.StatusPolicyViolation, "invalid message")
			return
		}
		switch v := payload.(type) {
		case *protocol.Heartbeat:
			if v.Epoch != p.epoch || v.DataTunnelID != p.tunnelID {
				ws.Close(websocket.StatusPolicyViolation, "stale epoch")
				return
			}
		case *protocol.SessionClose:
			if mt != protocol.TypeClosed || v.Epoch != p.epoch {
				continue // ignore commands from the agent and stale receipts
			}
			h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.session_closed", Result: "ok", SessionID: v.SessionID, AttemptID: v.AttemptID, Reason: v.Reason})
		default:
			ws.Close(websocket.StatusPolicyViolation, "unexpected message")
			return
		}
	}
}

func (h *Hub) gcTicketsLocked() {
	now := time.Now()
	for d, t := range h.tickets {
		if now.After(t.expires) {
			delete(h.tickets, d)
		}
	}
}

// HandleData serves /agent/v1/data: one long-lived smux tunnel per epoch.
func (h *Hub) HandleData(w http.ResponseWriter, r *http.Request) {
	host, cn, err := h.agentIdentity(r)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	auth := r.Header.Get("Authorization")
	tk, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || len(tk) < 16 || len(tk) > 2048 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	d := digest(tk)
	h.mu.Lock()
	t := h.tickets[d]
	delete(h.tickets, d) // consumed on first presentation, success or not
	p := h.byAgent[host.Agent.ID]
	var reason string
	switch {
	case t == nil:
		reason = "unknown_ticket"
	case time.Now().After(t.expires):
		reason = "expired_ticket"
	case subtle.ConstantTimeCompare([]byte(t.agentID), []byte(host.Agent.ID)) != 1 || t.hostID != host.ID:
		reason = "ticket_identity_mismatch"
	case t.ownerID != h.cfg.ServerID:
		reason = "wrong_owner"
	case p == nil || p.epoch != t.epoch || p.tunnelID != t.tunnelID || p.ctx.Err() != nil:
		reason = "stale_epoch"
	case p.mux != nil:
		reason = "tunnel_exists"
	}
	h.mu.Unlock()
	if reason != "" {
		h.audit.Record(audit.Event{Actor: "agent:" + cn, Action: "agent.data_ticket", Result: "denied", Target: host.ID, Reason: reason})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.SubprotocolData}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	if ws.Subprotocol() != protocol.SubprotocolData {
		ws.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}
	mux, err := tunnel.NewGatewayMux(p.ctx, ws, h.cfg.Mux)
	if err != nil {
		ws.Close(websocket.StatusInternalError, "mux")
		return
	}
	h.mu.Lock()
	installed := h.byAgent[p.agentID] == p && p.mux == nil && p.ctx.Err() == nil
	if installed {
		p.mux = mux
	}
	h.mu.Unlock()
	if !installed {
		_ = mux.Close()
		return
	}
	h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.data_ticket", Result: "ok", Target: p.hostID, Extra: map[string]any{"epoch": p.epoch}})
	if err := p.send(p.ctx, protocol.TypeDataReady, protocol.DataReady{Epoch: p.epoch, DataTunnelID: p.tunnelID}); err != nil {
		p.cancel()
		return
	}
	h.notify(p.hostID)
	select {
	case <-mux.CloseChan():
		// A failed data tunnel ends the epoch: sessions on it fail and the
		// Agent re-registers with a new epoch (no transparent migration).
		p.cancel()
	case <-p.ctx.Done():
	}
}

// Stream is one acknowledged SSH stream. Close releases the quota slot.
type Stream struct {
	net.Conn
	HostID, AgentID, TunnelID string
	Epoch                     uint64
	StreamID                  uint32
	release                   func()
}

// CloseWrite half-closes the stream.
func (s *Stream) CloseWrite() error { return s.Conn.(*smux.Stream).CloseWrite() }

// Close closes this stream only; the shared tunnel stays up.
func (s *Stream) Close() error {
	err := s.Conn.Close()
	s.release()
	return err
}

// OpenStream opens an SSH stream to host for an attempt that the caller has
// already authorized.
func (h *Hub) OpenStream(ctx context.Context, hostID, sessionID, attemptID string) (*Stream, error) {
	host, ok := h.store.Current().Host(hostID)
	if !ok || host.Disabled {
		return nil, ErrNotReady
	}
	h.mu.Lock()
	p := h.byAgent[host.Agent.ID]
	var mux *smux.Session
	if p != nil && p.hostID == hostID && p.ctx.Err() == nil {
		mux = p.mux
	}
	h.mu.Unlock()
	if mux == nil || mux.IsClosed() {
		return nil, ErrNotReady
	}
	select {
	case p.sem <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	var once sync.Once
	release := func() { once.Do(func() { <-p.sem }) }
	st, err := tunnel.OpenSSHStream(ctx, mux, tunnel.OpenRequest{Version: 1, Type: "ssh.open", HostID: hostID, SessionID: sessionID, AttemptID: attemptID, Epoch: p.epoch}, h.cfg.StreamOpen)
	if err != nil {
		release()
		return nil, err
	}
	return &Stream{Conn: st, HostID: hostID, AgentID: p.agentID, TunnelID: p.tunnelID, Epoch: p.epoch, StreamID: st.ID(), release: release}, nil
}

// CloseAttempt asks the Agent to drop the attempt's stream/TCP. It only acts
// on the given epoch and is best effort; the Gateway closes its side itself.
func (h *Hub) CloseAttempt(agentID string, epoch uint64, sessionID, attemptID, reason string) {
	h.mu.Lock()
	p := h.byAgent[agentID]
	h.mu.Unlock()
	if p == nil || p.epoch != epoch || p.ctx.Err() != nil {
		return
	}
	if len(reason) > 256 {
		reason = reason[:256]
	}
	if err := p.send(p.ctx, protocol.TypeClose, protocol.SessionClose{Epoch: epoch, SessionID: sessionID, AttemptID: attemptID, Reason: reason}); err != nil {
		h.log.Warn("session.close delivery failed", "agent_id", agentID, "err", err)
	}
}

// AgentInfo describes a connected agent for diagnostics.
type AgentInfo struct {
	AgentID        string            `json:"agent_id"`
	HostID         string            `json:"host_id"`
	Epoch          uint64            `json:"connection_epoch"`
	DataReady      bool              `json:"data_ready"`
	AgentVersion   string            `json:"agent_version"`
	ReportedLabels map[string]string `json:"reported_labels"`
	ConnectedAt    time.Time         `json:"connected_at"`
	Streams        int               `json:"streams"`
}

// Agents lists connected agents.
func (h *Hub) Agents() []AgentInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]AgentInfo, 0, len(h.byAgent))
	for _, p := range h.byAgent {
		out = append(out, AgentInfo{AgentID: p.agentID, HostID: p.hostID, Epoch: p.epoch, DataReady: p.mux != nil && !p.mux.IsClosed(), AgentVersion: p.agentVersion, ReportedLabels: p.reportedLabels, ConnectedAt: p.connectedAt, Streams: len(p.sem)})
	}
	return out
}

// Shutdown ends every epoch.
func (h *Hub) Shutdown() {
	h.mu.Lock()
	ps := make([]*presence, 0, len(h.byAgent))
	for _, p := range h.byAgent {
		ps = append(ps, p)
	}
	h.mu.Unlock()
	for _, p := range ps {
		p.cancel()
	}
}

// String helps debugging.
func (s *Stream) String() string {
	return fmt.Sprintf("stream host=%s epoch=%d id=%d", s.HostID, s.Epoch, s.StreamID)
}
