// Package agent is the host Agent runtime: it maintains a single mTLS
// WebSocket (/agent/v1/tunnel) to the Server, keeps it alive via WebSocket
// Ping/Pong when idle, activates smux v2 on demand when the Server sends
// mux.open, hibernates smux on mux.close, and forwards each accepted stream
// strictly to the locally configured loopback sshd.
package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"

	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/tunnel"
)

// Options configures the Agent.
type Options struct {
	ServerURL       string // wss://server:8443 (no path)
	TLS             *tls.Config
	SSHTarget       string
	Labels          map[string]string
	Version         string
	MaxStreams      int
	Heartbeat       time.Duration // fallback ping interval when server does not dictate one
	StreamOpen      time.Duration
	TCPDial         time.Duration
	RelayDrain      time.Duration
	ReconnectJitter time.Duration // uniform jitter after healthy epoch ends (anti-thundering-herd); negative disables jitter
	ReconnectMax    time.Duration
	Mux             tunnel.MuxConfig
	Log             *slog.Logger
	// OnReady is called (if set) when an epoch finishes registration.
	OnReady func(epoch uint64)
}

func (o *Options) defaults() error {
	if !strings.HasPrefix(o.ServerURL, "wss://") {
		return errors.New("agent: server_url must be wss://")
	}
	o.ServerURL = strings.TrimRight(o.ServerURL, "/")
	if err := tunnel.ValidateTarget(o.SSHTarget); err != nil {
		return err
	}
	if o.MaxStreams <= 0 {
		o.MaxStreams = 32
	}
	if o.Heartbeat <= 0 {
		o.Heartbeat = 45 * time.Second
	}
	if o.StreamOpen <= 0 {
		o.StreamOpen = 10 * time.Second
	}
	if o.TCPDial <= 0 {
		o.TCPDial = 5 * time.Second
	}
	if o.RelayDrain <= 0 {
		o.RelayDrain = 5 * time.Second
	}
	if o.ReconnectJitter == 0 {
		o.ReconnectJitter = 30 * time.Second
	}
	if o.ReconnectMax <= 0 {
		o.ReconnectMax = time.Minute
	}
	if o.Mux == (tunnel.MuxConfig{}) {
		o.Mux = tunnel.DefaultMuxConfig()
	}
	if o.Labels == nil {
		o.Labels = map[string]string{}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return nil
}

// Run keeps the Agent registered until ctx ends, reconnecting with anti-herd
// random jitter and exponential backoff. Every reconnect is a new epoch; old
// streams are never migrated.
func Run(ctx context.Context, o Options) error {
	if err := o.defaults(); err != nil {
		return err
	}
	tr := &http.Transport{TLSClientConfig: o.TLS, Proxy: http.ProxyFromEnvironment}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		// Never follow redirects: prevents credential/redirect abuse.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	backoff := time.Second
	for {
		start := time.Now()
		err := runEpoch(ctx, client, o)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var wait time.Duration
		if time.Since(start) > 2*time.Minute {
			backoff = time.Second
			if o.ReconnectJitter > 0 {
				// Spread 50k+ fleet reconnects evenly over [0, ReconnectJitter]
				// after a server restart or network flap.
				wait = rand.N(o.ReconnectJitter + 1)
			} else {
				wait = backoff/2 + rand.N(backoff/2+1)
			}
		} else {
			wait = backoff/2 + rand.N(backoff/2+1)
			backoff = min(backoff*2, o.ReconnectMax)
		}
		o.Log.Warn("agent epoch ended; reconnecting", "err", err, "in", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

type agentMux struct {
	gen           uint32
	mux           *smux.Session
	expectedClose atomic.Bool
}

func runEpoch(parent context.Context, client *http.Client, o Options) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	ws, _, err := websocket.Dial(dialCtx, o.ServerURL+protocol.TunnelPath, &websocket.DialOptions{
		HTTPClient:      client,
		Subprotocols:    []string{protocol.SubprotocolTunnel},
		CompressionMode: websocket.CompressionDisabled,
	})
	dialCancel()
	if err != nil {
		return fmt.Errorf("tunnel dial: %w", err)
	}
	defer ws.CloseNow()
	if ws.Subprotocol() != protocol.SubprotocolTunnel {
		return errors.New("server did not accept tunnel subprotocol")
	}
	ws.SetReadLimit(protocol.MaxControlMessage)

	helloBytes, err := protocol.Encode(protocol.TypeHello, protocol.Hello{AgentVersion: o.Version, ReportedLabels: o.Labels})
	if err != nil {
		return fmt.Errorf("encode hello: %w", err)
	}
	hctx, hcancel := context.WithTimeout(ctx, 15*time.Second)
	err = ws.Write(hctx, websocket.MessageText, helloBytes)
	hcancel()
	if err != nil {
		return fmt.Errorf("hello: %w", err)
	}

	wctx, wcancel := context.WithTimeout(ctx, 15*time.Second)
	typ, data, err := ws.Read(wctx)
	wcancel()
	if err != nil || typ != websocket.MessageText {
		return fmt.Errorf("welcome: %w", err)
	}
	mt, payload, err := protocol.Decode(data)
	if err != nil || mt != protocol.TypeWelcome {
		return fmt.Errorf("invalid welcome: %v", err)
	}
	w := payload.(*protocol.Welcome)
	log := o.Log.With("host_id", w.HostID, "epoch", w.Epoch)

	demux := tunnel.NewDemux(ctx, ws, protocol.MaxControlMessage, protocol.MaxBinaryMessage)
	defer demux.Close()

	reg := tunnel.NewRegistry(o.MaxStreams)
	binding := tunnel.Binding{HostID: w.HostID, Epoch: w.Epoch}
	rejectSem := make(chan struct{}, 8)

	var (
		muxMu    sync.Mutex
		curMux   *agentMux
		handlers sync.WaitGroup
	)
	closeCurrentMux := func() {
		muxMu.Lock()
		am := curMux
		curMux = nil
		muxMu.Unlock()
		if am != nil {
			am.expectedClose.Store(true)
			_ = am.mux.Close()
			demux.Deactivate(am.gen)
		}
	}
	defer func() {
		cancel()
		reg.CloseAll()
		closeCurrentMux()
		done := make(chan struct{})
		go func() { handlers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			log.Warn("stream handlers still draining after epoch end")
		}
	}()

	// Keepalive via WebSocket native Ping/Pong (zero JSON traffic when idle).
	pingInterval := time.Duration(w.PingIntervalMs) * time.Millisecond
	if pingInterval <= 0 {
		pingInterval = o.Heartbeat
	}
	pingTimeout := time.Duration(w.PingTimeoutMs) * time.Millisecond
	if pingTimeout <= pingInterval {
		pingTimeout = pingInterval * 2
	}
	go func() {
		// Add small jitter so pings across 50k agents stay desynchronized.
		for {
			jitter := time.Duration(0)
			if j := pingInterval / 5; j > 0 {
				jitter = rand.N(j) - j/2
			}
			timer := time.NewTimer(pingInterval + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			pctx, pcancel := context.WithTimeout(ctx, min(pingTimeout/2, 15*time.Second))
			err := ws.Ping(pctx)
			pcancel()
			if err != nil {
				log.Warn("tunnel ping failed", "err", err)
				cancel()
				return
			}
		}
	}()

	log.Info("agent tunnel ready")
	if o.OnReady != nil {
		o.OnReady(w.Epoch)
	}

	return demux.Run(func(msg []byte) error {
		mt, payload, err := protocol.Decode(msg)
		if err != nil {
			return fmt.Errorf("control: %w", err)
		}
		switch v := payload.(type) {
		case *protocol.MuxOpen:
			if v.Epoch != w.Epoch {
				return fmt.Errorf("control: mux.open for wrong epoch %d", v.Epoch)
			}
			smuxCfg := tunnel.MuxConfig{
				MaxFrameSize:      v.Smux.MaxFrameSize,
				MaxReceiveBuffer:  v.Smux.MaxReceiveBuffer,
				MaxStreamBuffer:   v.Smux.MaxStreamBuffer,
				KeepAliveInterval: time.Duration(v.Smux.KeepAliveIntervalMs) * time.Millisecond,
				KeepAliveTimeout:  time.Duration(v.Smux.KeepAliveTimeoutMs) * time.Millisecond,
			}
			closeCurrentMux()
			pipeBuf := min(smuxCfg.MaxReceiveBuffer, 256*1024)
			// Must activate synchronously inside the read loop so the very next
			// binary frame carrying mux_gen=v.MuxGen is routed immediately.
			gc, err := demux.Activate(v.MuxGen, pipeBuf)
			if err != nil {
				return fmt.Errorf("control: activate mux gen %d: %w", v.MuxGen, err)
			}
			mux, err := tunnel.NewAgentMuxConn(gc, smuxCfg)
			if err != nil {
				demux.Deactivate(v.MuxGen)
				return fmt.Errorf("control: start smux gen %d: %w", v.MuxGen, err)
			}
			am := &agentMux{gen: v.MuxGen, mux: mux}
			muxMu.Lock()
			curMux = am
			muxMu.Unlock()
			handlers.Add(1)
			go func(am *agentMux) {
				defer handlers.Done()
				for {
					st, err := am.mux.AcceptStream()
					if err != nil {
						if !am.expectedClose.Load() && ctx.Err() == nil {
							log.Warn("smux generation ended unexpectedly", "gen", am.gen, "err", err)
							cancel()
						}
						return
					}
					if !reg.Reserve() {
						select {
						case rejectSem <- struct{}{}:
							handlers.Add(1)
							go func() {
								defer handlers.Done()
								defer func() { <-rejectSem }()
								tunnel.RejectStream(st, tunnel.CodeTooManyStreams, 2*time.Second)
							}()
						default:
							_ = st.Close()
						}
						continue
					}
					handlers.Add(1)
					go func() {
						defer handlers.Done()
						defer reg.Unreserve()
						err := tunnel.ServeSSHStream(ctx, st, tunnel.AgentOptions{
							Binding: binding, Target: o.SSHTarget, OpenTimeout: o.StreamOpen, DialTimeout: o.TCPDial, DrainTimeout: o.RelayDrain, Registry: reg,
						})
						if err != nil {
							log.Debug("stream ended", "code", tunnel.ErrorCode(err), "err", err)
						}
					}()
				}
			}(am)
			return nil

		case *protocol.MuxClose:
			if v.Epoch != w.Epoch {
				return nil
			}
			muxMu.Lock()
			var target *agentMux
			if curMux != nil && curMux.gen == v.MuxGen {
				target = curMux
				curMux = nil
			}
			muxMu.Unlock()
			if target != nil {
				target.expectedClose.Store(true)
				_ = target.mux.Close()
				demux.Deactivate(target.gen)
			}
			return nil

		case *protocol.SessionClose:
			if mt != protocol.TypeClose {
				return errors.New("control: unexpected session.closed from server")
			}
			if v.Epoch != w.Epoch {
				return nil // stale epoch command: never touches this epoch
			}
			reg.Close(v.SessionID, v.AttemptID)
			// Send the receipt asynchronously so the read loop can never block
			// waiting on writeMu while TCP backpressure builds up.
			receipt, err := protocol.Encode(protocol.TypeClosed, protocol.SessionClose{
				Epoch: w.Epoch, SessionID: v.SessionID, AttemptID: v.AttemptID, Reason: v.Reason,
			})
			if err == nil {
				go func() {
					sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
					defer scancel()
					_ = demux.SendText(sctx, receipt)
				}()
			}
			return nil

		default:
			return fmt.Errorf("control: unexpected %s", mt)
		}
	}, nil)
}
