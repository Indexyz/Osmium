// Package agent is the host Agent runtime: it registers over the control WSS
// with its mTLS identity, opens the shared data WSS with the one-time ticket,
// runs the smux server side and forwards each accepted stream to the locally
// configured sshd only.
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
	"time"

	"github.com/coder/websocket"

	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/tunnel"
)

// Options configures the Agent.
type Options struct {
	ServerURL    string // wss://server:8443 (no path)
	TLS          *tls.Config
	SSHTarget    string
	Labels       map[string]string
	Version      string
	MaxStreams   int
	Heartbeat    time.Duration
	StreamOpen   time.Duration
	TCPDial      time.Duration
	RelayDrain   time.Duration
	ReconnectMax time.Duration
	Mux          tunnel.MuxConfig
	Log          *slog.Logger
	// OnReady is called (if set) when an epoch's data tunnel is ready.
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
		o.Heartbeat = 10 * time.Second
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

// Run keeps the Agent registered until ctx ends, reconnecting with jittered
// exponential backoff. Every reconnect is a new epoch; old streams are never
// migrated.
func Run(ctx context.Context, o Options) error {
	if err := o.defaults(); err != nil {
		return err
	}
	backoff := time.Second
	for {
		start := time.Now()
		err := runEpoch(ctx, o)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) > 2*time.Minute {
			backoff = time.Second
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		o.Log.Warn("agent epoch ended; reconnecting", "err", err, "in", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		backoff = min(backoff*2, o.ReconnectMax)
	}
}

func (o *Options) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: o.TLS, Proxy: http.ProxyFromEnvironment},
		// Never follow redirects: they could leak the data ticket elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func send(ctx context.Context, ws *websocket.Conn, mu *sync.Mutex, typ string, payload any) error {
	b, err := protocol.Encode(typ, payload)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return ws.Write(ctx, websocket.MessageText, b)
}

func runEpoch(parent context.Context, o Options) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	client := o.httpClient()
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	ctrl, _, err := websocket.Dial(dialCtx, o.ServerURL+protocol.ControlPath, &websocket.DialOptions{
		HTTPClient: client, Subprotocols: []string{protocol.SubprotocolControl}, CompressionMode: websocket.CompressionDisabled,
	})
	dialCancel()
	if err != nil {
		return fmt.Errorf("control dial: %w", err)
	}
	defer ctrl.CloseNow()
	if ctrl.Subprotocol() != protocol.SubprotocolControl {
		return errors.New("server did not accept control subprotocol")
	}
	ctrl.SetReadLimit(protocol.MaxControlMessage)
	var wmu sync.Mutex
	if err := send(ctx, ctrl, &wmu, protocol.TypeHello, protocol.Hello{AgentVersion: o.Version, ReportedLabels: o.Labels}); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 15*time.Second)
	typ, data, err := ctrl.Read(wctx)
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

	// The data path is a fixed constant validated by protocol.Decode; it is
	// resolved against the configured server only.
	dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
	dataWS, _, err := websocket.Dial(dctx, o.ServerURL+w.DataPath, &websocket.DialOptions{
		HTTPClient: client, Subprotocols: []string{protocol.SubprotocolData}, CompressionMode: websocket.CompressionDisabled,
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + w.DataTicket}},
	})
	dcancel()
	if err != nil {
		return fmt.Errorf("data dial: %w", err)
	}
	if dataWS.Subprotocol() != protocol.SubprotocolData {
		dataWS.CloseNow()
		return errors.New("server did not accept data subprotocol")
	}
	mux, err := tunnel.NewAgentMux(ctx, dataWS, o.Mux)
	if err != nil {
		dataWS.CloseNow()
		return fmt.Errorf("smux: %w", err)
	}
	defer mux.Close()
	reg := tunnel.NewRegistry(o.MaxStreams)
	var handlers sync.WaitGroup
	defer func() {
		reg.CloseAll()
		_ = mux.Close()
		done := make(chan struct{})
		go func() { handlers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			log.Warn("stream handlers still draining after epoch end")
		}
	}()
	binding := tunnel.Binding{HostID: w.HostID, Epoch: w.Epoch}
	go func() {
		defer cancel()
		for {
			st, err := mux.AcceptStream()
			if err != nil {
				log.Warn("data tunnel ended", "err", err)
				return
			}
			if !reg.Reserve() {
				handlers.Add(1)
				go func() { defer handlers.Done(); tunnel.RejectStream(st, tunnel.CodeTooManyStreams, 2*time.Second) }()
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
	}()
	go func() {
		t := time.NewTicker(o.Heartbeat)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				hb := protocol.Heartbeat{Epoch: w.Epoch, DataTunnelID: w.DataTunnelID, DataConnected: !mux.IsClosed(), ActiveStreams: reg.Active()}
				if err := send(ctx, ctrl, &wmu, protocol.TypeHeartbeat, hb); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		typ, data, err := ctrl.Read(ctx)
		if err != nil {
			return fmt.Errorf("control: %w", err)
		}
		if typ != websocket.MessageText {
			return errors.New("control: binary message")
		}
		mt, payload, err := protocol.Decode(data)
		if err != nil {
			return fmt.Errorf("control: %w", err)
		}
		switch v := payload.(type) {
		case *protocol.DataReady:
			if v.Epoch != w.Epoch || v.DataTunnelID != w.DataTunnelID {
				return errors.New("control: data_ready for another epoch")
			}
			log.Info("data tunnel ready")
			if o.OnReady != nil {
				o.OnReady(w.Epoch)
			}
		case *protocol.SessionClose:
			if mt != protocol.TypeClose {
				return errors.New("control: unexpected session.closed from server")
			}
			if v.Epoch != w.Epoch {
				continue // stale epoch command: never touches this epoch
			}
			reg.Close(v.SessionID, v.AttemptID)
			_ = send(ctx, ctrl, &wmu, protocol.TypeClosed, protocol.SessionClose{Epoch: w.Epoch, SessionID: v.SessionID, AttemptID: v.AttemptID, Reason: v.Reason})
		default:
			return fmt.Errorf("control: unexpected %s", mt)
		}
	}
}
