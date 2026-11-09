package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"
)

// MuxConfig holds the smux parameters from trusted deployment configuration.
// Both ends must agree; the wire version is always 2.
type MuxConfig struct {
	MaxFrameSize      int
	MaxReceiveBuffer  int
	MaxStreamBuffer   int
	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration
}

// DefaultMuxConfig returns the experimental starting point from docs/05 §4.
func DefaultMuxConfig() MuxConfig {
	return MuxConfig{
		MaxFrameSize:      16 * 1024,
		MaxReceiveBuffer:  4 * 1024 * 1024,
		MaxStreamBuffer:   256 * 1024,
		KeepAliveInterval: 10 * time.Second,
		KeepAliveTimeout:  30 * time.Second,
	}
}

func (c MuxConfig) smux() (*smux.Config, error) {
	s := smux.DefaultConfig()
	s.Version = 2
	s.MaxFrameSize = c.MaxFrameSize
	s.MaxReceiveBuffer = c.MaxReceiveBuffer
	s.MaxStreamBuffer = c.MaxStreamBuffer
	s.KeepAliveInterval = c.KeepAliveInterval
	s.KeepAliveTimeout = c.KeepAliveTimeout
	if err := smux.VerifyConfig(s); err != nil {
		return nil, err
	}
	return s, nil
}

// NewGatewayMux wraps an authenticated data WebSocket as the smux client side.
// ctx must belong to the whole Agent tunnel, never to one SSH session.
// It also supervises the session: smux does not close a Session on a socket
// read or protocol error, and the Agent must never open streams towards the
// Gateway, so either condition closes the whole tunnel (CloseChan fires).
func NewGatewayMux(ctx context.Context, ws *websocket.Conn, c MuxConfig) (*smux.Session, error) {
	mux, err := newMux(ctx, ws, c, smux.Client)
	if err != nil {
		return nil, err
	}
	go func() {
		defer mux.Close()
		if st, err := mux.AcceptStream(); err == nil {
			_ = st.Close()
		}
	}()
	return mux, nil
}

// NewAgentMux wraps the data WebSocket as the smux server side. The Agent dials
// the WebSocket but accepts streams opened by the Gateway.
func NewAgentMux(ctx context.Context, ws *websocket.Conn, c MuxConfig) (*smux.Session, error) {
	return newMux(ctx, ws, c, smux.Server)
}

func newMux(ctx context.Context, ws *websocket.Conn, c MuxConfig, mk func(io.ReadWriteCloser, *smux.Config) (*smux.Session, error)) (*smux.Session, error) {
	cfg, err := c.smux()
	if err != nil {
		return nil, err
	}
	raw := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	mux, err := mk(raw, cfg)
	if err != nil {
		_ = raw.Close()
	}
	return mux, err
}

// guard applies a phase deadline to one stream only; stop waits for a racing
// cancellation callback so the caller can safely clear the deadline afterwards.
func guard(ctx context.Context, st net.Conn, timeout time.Duration) func() {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = st.SetDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = st.SetDeadline(time.Now())
		close(done)
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}

// RejectedError is returned by OpenSSHStream when the Agent answered ok=false.
type RejectedError struct{ Code string }

func (e *RejectedError) Error() string { return "agent rejected stream: " + e.Code }

// OpenSSHStream opens one stream for an already-authorized attempt and performs
// the open/ack exchange. On success the stream carries raw SSH bytes only and
// has no deadline; the caller owns it and must apply its own phase deadlines.
func OpenSSHStream(ctx context.Context, mux *smux.Session, q OpenRequest, timeout time.Duration) (_ *smux.Stream, err error) {
	if timeout <= 0 {
		return nil, errors.New("positive open timeout required")
	}
	if err := q.Validate(Binding{HostID: q.HostID, Epoch: q.Epoch}); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st, err := mux.OpenStream() // smux exposes no context parameter here.
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() {
		if err != nil {
			_ = st.Close()
		}
	}()
	stop := guard(ctx, st, timeout)
	defer stop()
	if err = WritePrelude(st, q); err != nil {
		return nil, err
	}
	var ack OpenResult
	if err = ReadPrelude(st, &ack); err != nil {
		return nil, err
	}
	if err = ack.Validate(q); err != nil {
		return nil, err
	}
	if !ack.OK {
		return nil, &RejectedError{Code: ack.Code}
	}
	stop()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = st.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return st, nil
}
