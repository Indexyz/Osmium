// Package agenthub manages Agent presence on the Server over a single mTLS
// WebSocket (/agent/v1/tunnel) per Agent epoch:
//   - 256-sharded presence table (no single global lock on hot paths),
//   - single background liveness reaper using lock-free atomic timestamps,
//   - token-bucket admission rate limiting against reconnect storms,
//   - on-demand smux v2 activation with idle hibernation (zero smux overhead
//     for idle hosts), and per-host active/pending stream quotas.
package agenthub

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/tunnel"
)

const hubShardCount = 256

// Errors returned by OpenStream.
var (
	ErrNotReady = errors.New("host agent is not ready")
	ErrBusy     = errors.New("host stream quota exhausted")
)

// Config tunes the hub.
type Config struct {
	ServerID          string
	Mux               tunnel.MuxConfig
	HelloTimeout      time.Duration
	PingInterval      time.Duration // advertised to Agents in agent.welcome
	HeartbeatTimeout  time.Duration // liveness timeout without Ping or frames
	MuxIdleTTL        time.Duration // idle delay after last stream before hibernating smux (0 = keep open)
	StreamOpen        time.Duration
	MaxStreams        int     // per Agent epoch, pending + active
	MaxPendingStreams int     // per Agent epoch, unauthenticated streams (protects sshd MaxStartups)
	AcceptRate        float64 // max new Agent tunnels per second (0 = unlimited)
	AcceptBurst       int     // token bucket burst size
	// Deprecated: TicketTTL is accepted for config compatibility and ignored in
	// the unified single-WSS protocol.
	TicketTTL time.Duration
}

func (c *Config) defaults() {
	if c.ServerID == "" {
		c.ServerID = "server-1"
	}
	if c.Mux == (tunnel.MuxConfig{}) {
		c.Mux = tunnel.DefaultMuxConfig()
	}
	if c.HelloTimeout <= 0 {
		c.HelloTimeout = 10 * time.Second
	}
	if c.HeartbeatTimeout <= 0 {
		c.HeartbeatTimeout = 135 * time.Second
	}
	if c.PingInterval <= 0 {
		c.PingInterval = c.HeartbeatTimeout / 3
		if c.PingInterval < 200*time.Millisecond {
			c.PingInterval = 200 * time.Millisecond
		}
		if c.PingInterval > 45*time.Second {
			c.PingInterval = 45 * time.Second
		}
	}
	if c.HeartbeatTimeout < c.PingInterval*2 {
		c.HeartbeatTimeout = c.PingInterval * 2
	}
	if c.MuxIdleTTL == 0 {
		c.MuxIdleTTL = 60 * time.Second
	}
	if c.StreamOpen <= 0 {
		c.StreamOpen = 10 * time.Second
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 32
	}
	if c.MaxPendingStreams <= 0 {
		c.MaxPendingStreams = min(8, c.MaxStreams)
	}
	if c.MaxPendingStreams > c.MaxStreams {
		c.MaxPendingStreams = c.MaxStreams
	}
	if c.AcceptRate < 0 {
		c.AcceptRate = 0
	}
	if c.AcceptRate > 0 && c.AcceptBurst <= 0 {
		c.AcceptBurst = max(1, int(c.AcceptRate*2))
	}
}

type hubShard struct {
	mu      sync.RWMutex
	byAgent map[string]*presence
}

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = max(1, int(rate))
	}
	return &tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (b *tokenBucket) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	if elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Hub is the sharded Agent connection manager.
type Hub struct {
	cfg     Config
	store   *authz.Store
	audit   *audit.Logger
	log     *slog.Logger
	limiter *tokenBucket

	epoch  atomic.Uint64
	shards [hubShardCount]hubShard

	changeMu sync.RWMutex
	onChange []func(hostID string)

	stopReaper chan struct{}
	reaperDone chan struct{}
	stopOnce   sync.Once
	activeWG   sync.WaitGroup
}

type activeMux struct {
	gen           uint32
	mux           *smux.Session
	expectedClose atomic.Bool
}

type presence struct {
	agentID, hostID, cn string
	epoch               uint64
	tunnelID            string
	ctx                 context.Context
	cancel              context.CancelFunc
	demux               *tunnel.Demux
	sem                 chan struct{}
	pendingSem          chan struct{}
	agentVersion        string
	reportedLabels      map[string]string
	connectedAt         time.Time
	lastSeenUnixNano    atomic.Int64

	muxMu         sync.Mutex
	muxGen        uint32
	mux           *activeMux
	activeStreams int
	idleTimer     *time.Timer
}

// New creates a sharded hub, starts its single background liveness reaper, and
// subscribes it to policy changes.
func New(cfg Config, store *authz.Store, a *audit.Logger, log *slog.Logger) *Hub {
	cfg.defaults()
	h := &Hub{
		cfg:        cfg,
		store:      store,
		audit:      a,
		log:        log,
		limiter:    newTokenBucket(cfg.AcceptRate, cfg.AcceptBurst),
		stopReaper: make(chan struct{}),
		reaperDone: make(chan struct{}),
	}
	// Seed epoch from millisecond wall clock so restarts never reset epochs
	// back to 1 and collide in audit trails.
	h.epoch.Store(uint64(time.Now().UnixMilli()))
	for i := range h.shards {
		h.shards[i].byAgent = make(map[string]*presence)
	}
	store.OnChange(h.reconcilePolicy)
	go h.reapLoop()
	return h
}

func shardIndex(agentID string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentID))
	return int(h.Sum32() & (hubShardCount - 1))
}

func (h *Hub) shard(agentID string) *hubShard {
	return &h.shards[shardIndex(agentID)]
}

func (h *Hub) reapLoop() {
	defer close(h.reaperDone)
	interval := h.cfg.HeartbeatTimeout / 4
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-h.stopReaper:
			return
		case <-t.C:
			cutoff := time.Now().Add(-h.cfg.HeartbeatTimeout).UnixNano()
			var expired []*presence
			for i := range h.shards {
				sh := &h.shards[i]
				sh.mu.RLock()
				for _, p := range sh.byAgent {
					if p.lastSeenUnixNano.Load() < cutoff {
						expired = append(expired, p)
					}
				}
				sh.mu.RUnlock()
			}
			for _, p := range expired {
				h.log.Warn("closing agent epoch: heartbeat timeout", "agent_id", p.agentID, "host_id", p.hostID, "epoch", p.epoch)
				p.cancel()
			}
		}
	}
}

// OnStatusChange registers a callback fired when a host's status changes.
func (h *Hub) OnStatusChange(f func(hostID string)) {
	h.changeMu.Lock()
	h.onChange = append(h.onChange, f)
	h.changeMu.Unlock()
}

func (h *Hub) notify(hostID string) {
	h.changeMu.RLock()
	if len(h.onChange) == 0 {
		h.changeMu.RUnlock()
		return
	}
	fs := append([]func(string){}, h.onChange...)
	h.changeMu.RUnlock()
	for _, f := range fs {
		f(hostID)
	}
}

// ReconcileHost checks a single agent/host binding against snap without
// scanning every shard (used by incremental admin host updates).
func (h *Hub) ReconcileHost(snap *authz.Snapshot, agentID string) {
	sh := h.shard(agentID)
	sh.mu.RLock()
	p := sh.byAgent[agentID]
	sh.mu.RUnlock()
	if p == nil {
		return
	}
	host, ok := snap.HostByAgentCN(p.cn)
	if !ok || host.ID != p.hostID || host.Agent.ID != p.agentID || host.Disabled {
		h.log.Info("closing agent epoch after host change", "agent_id", p.agentID, "epoch", p.epoch)
		p.cancel()
	}
}

// reconcilePolicy ends epochs whose host was removed, disabled or rebound.
func (h *Hub) reconcilePolicy(s *authz.Snapshot) {
	var stale []*presence
	for i := range h.shards {
		sh := &h.shards[i]
		sh.mu.RLock()
		for _, p := range sh.byAgent {
			host, ok := s.HostByAgentCN(p.cn)
			if !ok || host.ID != p.hostID || host.Agent.ID != p.agentID || host.Disabled {
				stale = append(stale, p)
			}
		}
		sh.mu.RUnlock()
	}
	for _, p := range stale {
		h.log.Info("closing agent epoch after policy change", "agent_id", p.agentID, "epoch", p.epoch)
		p.cancel()
	}
}

// Status returns the host status for the directory. Under the single-WSS
// protocol an authenticated Agent is immediately "ready" (smux activates on
// demand when the first SSH stream opens).
func (h *Hub) Status(host *authz.Host) string {
	if host.Disabled {
		return "disabled"
	}
	sh := h.shard(host.Agent.ID)
	sh.mu.RLock()
	p := sh.byAgent[host.Agent.ID]
	ok := p != nil && p.hostID == host.ID && p.ctx.Err() == nil
	sh.mu.RUnlock()
	if !ok {
		return "offline"
	}
	return "ready"
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

func (p *presence) send(ctx context.Context, typ string, payload any) error {
	b, err := protocol.Encode(typ, payload)
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.demux.SendText(sctx, b)
}

func (p *presence) touch() {
	p.lastSeenUnixNano.Store(time.Now().UnixNano())
}

func (p *presence) closeMuxLocked(reason string) {
	if p.idleTimer != nil {
		p.idleTimer.Stop()
		p.idleTimer = nil
	}
	if p.mux == nil {
		return
	}
	am := p.mux
	p.mux = nil
	am.expectedClose.Store(true)
	_ = am.mux.Close()
	p.demux.Deactivate(am.gen)
}

// HandleTunnel serves GET /agent/v1/tunnel on the mTLS listener: one long-lived
// WSS per Agent epoch carrying control text frames, WebSocket Ping/Pong
// keepalives, and on-demand generational smux v2 binary frames.
func (h *Hub) HandleTunnel(w http.ResponseWriter, r *http.Request) {
	if !h.limiter.allow() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many agent connections", http.StatusServiceUnavailable)
		return
	}
	host, cn, err := h.agentIdentity(r)
	if err != nil {
		h.audit.Record(audit.Event{Actor: "agent:" + cn, Action: "agent.register", Result: "denied", Reason: err.Error()})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var pRef atomic.Pointer[presence]
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{protocol.SubprotocolTunnel},
		CompressionMode: websocket.CompressionDisabled,
		OnPingReceived: func(_ context.Context, _ []byte) bool {
			if p := pRef.Load(); p != nil {
				p.touch()
			}
			return true
		},
	})
	if err != nil {
		return
	}
	if ws.Subprotocol() != protocol.SubprotocolTunnel {
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
	demux := tunnel.NewDemux(ctx, ws, protocol.MaxControlMessage, protocol.MaxBinaryMessage)
	ep := h.epoch.Add(1)
	p := &presence{
		agentID:        host.Agent.ID,
		hostID:         host.ID,
		cn:             cn,
		epoch:          ep,
		tunnelID:       "t-" + randomToken(9),
		ctx:            ctx,
		cancel:         cancel,
		demux:          demux,
		sem:            make(chan struct{}, h.cfg.MaxStreams),
		pendingSem:     make(chan struct{}, h.cfg.MaxPendingStreams),
		agentVersion:   hello.AgentVersion,
		reportedLabels: cloneMap(hello.ReportedLabels),
		connectedAt:    time.Now(),
	}
	p.touch()
	pRef.Store(p)

	h.activeWG.Add(1)
	defer h.activeWG.Done()

	sh := h.shard(p.agentID)
	sh.mu.Lock()
	old := sh.byAgent[p.agentID]
	sh.byAgent[p.agentID] = p
	sh.mu.Unlock()
	if old != nil {
		h.log.Warn("agent registration superseded existing epoch (possible duplicate credential or fast reconnect)", "agent_id", p.agentID, "host_id", p.hostID, "old_epoch", old.epoch, "new_epoch", p.epoch)
		h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.superseded", Result: "ok", Target: p.hostID, Extra: map[string]any{"old_epoch": old.epoch, "new_epoch": p.epoch}})
		old.cancel()
	}
	h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.register", Result: "ok", Target: p.hostID, Extra: map[string]any{"epoch": p.epoch, "agent_version": p.agentVersion}})

	// Use context.AfterFunc instead of spawning an extra long-lived goroutine
	// per idle Agent (keeps 50k+ idle Agents at 1 goroutine each).
	stopClose := context.AfterFunc(ctx, func() {
		p.muxMu.Lock()
		p.closeMuxLocked("epoch_ended")
		p.muxMu.Unlock()
		demux.Close()
		_ = ws.Close(websocket.StatusGoingAway, "epoch ended")
	})
	defer func() {
		cancel()
		stopClose()
		p.muxMu.Lock()
		p.closeMuxLocked("epoch_ended")
		p.muxMu.Unlock()
		demux.Close()
		_ = ws.CloseNow()
		sh.mu.Lock()
		if sh.byAgent[p.agentID] == p {
			delete(sh.byAgent, p.agentID)
		}
		sh.mu.Unlock()
		h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.disconnect", Result: "ok", Target: p.hostID, Extra: map[string]any{"epoch": p.epoch}})
		h.notify(p.hostID)
	}()

	welcome := protocol.Welcome{
		AgentID:        p.agentID,
		HostID:         p.hostID,
		Epoch:          p.epoch,
		TunnelID:       p.tunnelID,
		SmuxVersion:    2,
		PingIntervalMs: int(h.cfg.PingInterval / time.Millisecond),
		PingTimeoutMs:  int(h.cfg.HeartbeatTimeout / time.Millisecond),
	}
	if err := p.send(ctx, protocol.TypeWelcome, welcome); err != nil {
		return
	}
	h.notify(p.hostID)

	_ = demux.Run(func(msg []byte) error {
		mt, payload, err := protocol.Decode(msg)
		if err != nil {
			_ = ws.Close(websocket.StatusPolicyViolation, "invalid message")
			return err
		}
		switch v := payload.(type) {
		case *protocol.SessionClose:
			if mt != protocol.TypeClosed || v.Epoch != p.epoch {
				return nil // ignore commands from the agent and stale receipts
			}
			h.audit.Record(audit.Event{Actor: "agent:" + p.agentID, Action: "agent.session_closed", Result: "ok", SessionID: v.SessionID, AttemptID: v.AttemptID, Reason: v.Reason})
			return nil
		default:
			_ = ws.Close(websocket.StatusPolicyViolation, "unexpected message")
			return fmt.Errorf("unexpected control message %s", mt)
		}
	}, p.touch)
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (h *Hub) smuxParams() protocol.SmuxParams {
	return protocol.SmuxParams{
		MaxFrameSize:        h.cfg.Mux.MaxFrameSize,
		MaxReceiveBuffer:    h.cfg.Mux.MaxReceiveBuffer,
		MaxStreamBuffer:     h.cfg.Mux.MaxStreamBuffer,
		KeepAliveIntervalMs: int(h.cfg.Mux.KeepAliveInterval / time.Millisecond),
		KeepAliveTimeoutMs:  int(h.cfg.Mux.KeepAliveTimeout / time.Millisecond),
	}
}

// acquireMux increments p.activeStreams and ensures an active smux v2 session
// exists on p (activating a new generation on demand with 0-RTT mux.open).
func (h *Hub) acquireMux(ctx context.Context, p *presence) (*smux.Session, uint32, error) {
	p.muxMu.Lock()
	defer p.muxMu.Unlock()
	if p.ctx.Err() != nil {
		return nil, 0, ErrNotReady
	}
	if p.idleTimer != nil {
		p.idleTimer.Stop()
		p.idleTimer = nil
	}
	if p.mux != nil && !p.mux.mux.IsClosed() {
		p.activeStreams++
		return p.mux.mux, p.mux.gen, nil
	}
	// Clean up any closed residue before opening a fresh generation.
	if p.mux != nil {
		p.closeMuxLocked("reopen")
	}
	p.muxGen++
	gen := p.muxGen
	openFrame, err := protocol.Encode(protocol.TypeMuxOpen, protocol.MuxOpen{
		Epoch:  p.epoch,
		MuxGen: gen,
		Smux:   h.smuxParams(),
	})
	if err != nil {
		return nil, 0, err
	}
	pipeBuf := min(h.cfg.Mux.MaxReceiveBuffer, 256*1024)
	sctx, cancel := context.WithTimeout(ctx, min(h.cfg.StreamOpen, 5*time.Second))
	gc, err := p.demux.ActivateAndSendText(sctx, gen, pipeBuf, openFrame)
	cancel()
	if err != nil {
		return nil, 0, fmt.Errorf("activate mux: %w", err)
	}
	mux, err := tunnel.NewGatewayMuxConn(gc, h.cfg.Mux)
	if err != nil {
		p.demux.Deactivate(gen)
		return nil, 0, err
	}
	am := &activeMux{gen: gen, mux: mux}
	p.mux = am
	p.activeStreams++
	go h.superviseMux(p, am)
	return mux, gen, nil
}

func (h *Hub) superviseMux(p *presence, am *activeMux) {
	st, err := am.mux.AcceptStream()
	if err == nil {
		// The Agent must never open streams toward the Gateway.
		_ = st.Close()
		h.log.Warn("closing agent epoch: agent opened unauthorized stream", "agent_id", p.agentID, "epoch", p.epoch)
		p.cancel()
		return
	}
	if !am.expectedClose.Load() && p.ctx.Err() == nil {
		h.log.Warn("closing agent epoch: unexpected mux error", "agent_id", p.agentID, "epoch", p.epoch, "gen", am.gen, "err", err)
		p.cancel()
	}
}

func (h *Hub) releaseMuxRef(p *presence, gen uint32) {
	p.muxMu.Lock()
	if p.activeStreams > 0 {
		p.activeStreams--
	}
	if p.activeStreams == 0 && p.mux != nil && p.mux.gen == gen && h.cfg.MuxIdleTTL > 0 && p.ctx.Err() == nil {
		if p.idleTimer != nil {
			p.idleTimer.Stop()
		}
		p.idleTimer = time.AfterFunc(h.cfg.MuxIdleTTL, func() {
			h.retireIdleMux(p, gen)
		})
	}
	p.muxMu.Unlock()
}

func (h *Hub) retireIdleMux(p *presence, gen uint32) {
	p.muxMu.Lock()
	if p.activeStreams > 0 || p.mux == nil || p.mux.gen != gen {
		p.muxMu.Unlock()
		return
	}
	am := p.mux
	p.mux = nil
	p.idleTimer = nil
	am.expectedClose.Store(true)
	p.muxMu.Unlock()

	if p.ctx.Err() == nil {
		_ = p.send(p.ctx, protocol.TypeMuxClose, protocol.MuxClose{Epoch: p.epoch, MuxGen: gen, Reason: "idle"})
	}
	_ = am.mux.Close()
	p.demux.Deactivate(gen)
}

// Stream is one acknowledged SSH stream. Close releases the quota slot and
// schedules idle mux hibernation when the host has no remaining streams.
type Stream struct {
	net.Conn
	HostID, AgentID, TunnelID string
	Epoch                     uint64
	MuxGen                    uint32
	StreamID                  uint32
	release                   func()
	releasePending            func()
}

// CloseWrite half-closes the stream.
func (s *Stream) CloseWrite() error { return s.Conn.(*smux.Stream).CloseWrite() }

// MarkAuthenticated releases this stream's unauthenticated-pending quota slot
// once SSH authentication has completed (or native handoff is active). Safe to
// call multiple times.
func (s *Stream) MarkAuthenticated() {
	if s.releasePending != nil {
		s.releasePending()
	}
}

// Close closes this stream only; the shared tunnel stays up.
func (s *Stream) Close() error {
	err := s.Conn.Close()
	if s.releasePending != nil {
		s.releasePending()
	}
	if s.release != nil {
		s.release()
	}
	return err
}

// OpenStream opens an SSH stream to host for an attempt that the caller has
// already authorized, activating smux v2 on demand if the host was idle.
func (h *Hub) OpenStream(ctx context.Context, hostID, sessionID, attemptID string) (*Stream, error) {
	host, ok := h.store.Current().Host(hostID)
	if !ok || host.Disabled {
		return nil, ErrNotReady
	}
	sh := h.shard(host.Agent.ID)
	sh.mu.RLock()
	p := sh.byAgent[host.Agent.ID]
	sh.mu.RUnlock()
	if p == nil || p.hostID != hostID || p.ctx.Err() != nil {
		return nil, ErrNotReady
	}
	select {
	case p.pendingSem <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	var pendingOnce sync.Once
	releasePending := func() { pendingOnce.Do(func() { <-p.pendingSem }) }
	select {
	case p.sem <- struct{}{}:
	default:
		releasePending()
		return nil, ErrBusy
	}
	mux, gen, err := h.acquireMux(ctx, p)
	if err != nil {
		releasePending()
		<-p.sem
		return nil, err
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			<-p.sem
			h.releaseMuxRef(p, gen)
		})
	}
	st, err := tunnel.OpenSSHStream(ctx, mux, tunnel.OpenRequest{
		Version: 1, Type: "ssh.open", HostID: hostID, SessionID: sessionID, AttemptID: attemptID, Epoch: p.epoch,
	}, h.cfg.StreamOpen)
	if err != nil {
		releasePending()
		release()
		return nil, err
	}
	return &Stream{
		Conn: st, HostID: hostID, AgentID: p.agentID, TunnelID: p.tunnelID,
		Epoch: p.epoch, MuxGen: gen, StreamID: st.ID(),
		release: release, releasePending: releasePending,
	}, nil
}

// CloseAttempt asks the Agent to drop the attempt's stream/TCP. It only acts
// on the given epoch. If control delivery fails/times out (e.g. severe TCP
// congestion), it tears down the epoch to guarantee no orphaned sshd session.
func (h *Hub) CloseAttempt(agentID string, epoch uint64, sessionID, attemptID, reason string) {
	sh := h.shard(agentID)
	sh.mu.RLock()
	p := sh.byAgent[agentID]
	sh.mu.RUnlock()
	if p == nil || p.epoch != epoch || p.ctx.Err() != nil {
		return
	}
	if len(reason) > 256 {
		reason = reason[:256]
	}
	if err := p.send(p.ctx, protocol.TypeClose, protocol.SessionClose{Epoch: epoch, SessionID: sessionID, AttemptID: attemptID, Reason: reason}); err != nil {
		h.log.Warn("session.close delivery failed; terminating agent epoch to prevent orphan session", "agent_id", agentID, "epoch", epoch, "err", err)
		p.cancel()
	}
}

// AgentInfo describes a connected agent for diagnostics.
type AgentInfo struct {
	AgentID        string            `json:"agent_id"`
	HostID         string            `json:"host_id"`
	Epoch          uint64            `json:"connection_epoch"`
	DataReady      bool              `json:"data_ready"`
	MuxActive      bool              `json:"mux_active"`
	MuxGen         uint32            `json:"mux_gen,omitempty"`
	AgentVersion   string            `json:"agent_version"`
	ReportedLabels map[string]string `json:"reported_labels"`
	ConnectedAt    time.Time         `json:"connected_at"`
	Streams        int               `json:"streams"`
	PendingStreams int               `json:"pending_streams"`
}

func snapshotAgent(p *presence) AgentInfo {
	p.muxMu.Lock()
	muxActive := p.mux != nil && !p.mux.mux.IsClosed()
	muxGen := p.muxGen
	p.muxMu.Unlock()
	return AgentInfo{
		AgentID:        p.agentID,
		HostID:         p.hostID,
		Epoch:          p.epoch,
		DataReady:      p.ctx.Err() == nil,
		MuxActive:      muxActive,
		MuxGen:         muxGen,
		AgentVersion:   p.agentVersion,
		ReportedLabels: cloneMap(p.reportedLabels),
		ConnectedAt:    p.connectedAt,
		Streams:        len(p.sem),
		PendingStreams: len(p.pendingSem),
	}
}

// Agents lists all connected agents sorted by agent_id.
func (h *Hub) Agents() []AgentInfo {
	var out []AgentInfo
	for i := range h.shards {
		sh := &h.shards[i]
		sh.mu.RLock()
		for _, p := range sh.byAgent {
			out = append(out, snapshotAgent(p))
		}
		sh.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

// AgentsPageQuery filters and paginates connected agents.
type AgentsPageQuery struct {
	Query  string // case-insensitive substring match against agent_id or host_id
	Cursor string // exclusive lower bound on agent_id
	Limit  int    // 1..1000
}

// AgentsPageResult holds one page of connected agents.
type AgentsPageResult struct {
	Items      []AgentInfo `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
	Total      int         `json:"total"`
}

// AgentsPage returns a bounded, cursor-paginated slice of connected agents.
func (h *Hub) AgentsPage(q AgentsPageQuery) AgentsPageResult {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	needle := strings.ToLower(strings.TrimSpace(q.Query))
	var matched []*presence
	for i := range h.shards {
		sh := &h.shards[i]
		sh.mu.RLock()
		for _, p := range sh.byAgent {
			if needle != "" &&
				!strings.Contains(strings.ToLower(p.agentID), needle) &&
				!strings.Contains(strings.ToLower(p.hostID), needle) {
				continue
			}
			matched = append(matched, p)
		}
		sh.mu.RUnlock()
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].agentID < matched[j].agentID })
	total := len(matched)

	start := 0
	if q.Cursor != "" {
		start = sort.Search(len(matched), func(i int) bool { return matched[i].agentID > q.Cursor })
	}
	end := min(start+q.Limit, len(matched))
	items := make([]AgentInfo, 0, max(0, end-start))
	for _, p := range matched[start:end] {
		items = append(items, snapshotAgent(p))
	}
	var next string
	if end < len(matched) && len(items) > 0 {
		next = items[len(items)-1].AgentID
	}
	return AgentsPageResult{Items: items, NextCursor: next, Total: total}
}

// Count returns the number of currently registered Agents across all shards.
func (h *Hub) Count() int {
	n := 0
	for i := range h.shards {
		sh := &h.shards[i]
		sh.mu.RLock()
		n += len(sh.byAgent)
		sh.mu.RUnlock()
	}
	return n
}

// Shutdown stops the background reaper and ends every active Agent epoch.
func (h *Hub) Shutdown() {
	h.stopOnce.Do(func() { close(h.stopReaper) })
	<-h.reaperDone
	var ps []*presence
	for i := range h.shards {
		sh := &h.shards[i]
		sh.mu.RLock()
		for _, p := range sh.byAgent {
			ps = append(ps, p)
		}
		sh.mu.RUnlock()
	}
	for _, p := range ps {
		p.cancel()
	}
}

// Wait blocks until all active Agent tunnel handlers have finished their
// cleanup (including disconnect audit events), or until timeout elapses.
func (h *Hub) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		h.activeWG.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// String helps debugging.
func (s *Stream) String() string {
	return fmt.Sprintf("stream host=%s epoch=%d gen=%d id=%d", s.HostID, s.Epoch, s.MuxGen, s.StreamID)
}
