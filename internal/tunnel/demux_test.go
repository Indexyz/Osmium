package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"
)

func demuxPair(t *testing.T, onServerText, onClientText func(*Demux, []byte) error) (srvDemux, cliDemux *Demux, srvWS, cliWS *websocket.Conn) {
	t.Helper()
	srvReady := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"web-ssh-tunnel.v2"}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		d := NewDemux(context.Background(), ws, 64*1024, 128*1024)
		srvDemux, srvWS = d, ws
		close(srvReady)
		_ = d.Run(func(b []byte) error {
			if onServerText != nil {
				return onServerText(d, b)
			}
			return nil
		}, nil)
	}))
	t.Cleanup(srv.Close)

	cws, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{
		Subprotocols: []string{"web-ssh-tunnel.v2"}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	<-srvReady
	cliDemux, cliWS = NewDemux(context.Background(), cws, 64*1024, 128*1024), cws
	go func() {
		_ = cliDemux.Run(func(b []byte) error {
			if onClientText != nil {
				return onClientText(cliDemux, b)
			}
			return nil
		}, nil)
	}()
	t.Cleanup(func() {
		cliDemux.Close()
		srvDemux.Close()
		_ = cliWS.CloseNow()
		_ = srvWS.CloseNow()
	})
	return srvDemux, cliDemux, srvWS, cliWS
}

// Verify on-demand activation, stream traffic, idle deactivation without closing
// the WSS, late stale-generation frame drop, and clean re-activation on gen=2.
func TestDemuxOnDemandLifecycleAndStaleGenDrop(t *testing.T) {
	target := newEchoTarget(t, "")
	reg := NewRegistry(8)
	var mu sync.Mutex
	var agentMux *smux.Session

	onAgentText := func(d *Demux, b []byte) error {
		msg := string(b)
		switch {
		case strings.HasPrefix(msg, "open:"):
			gen := uint32(msg[5] - '0')
			gc, err := d.Activate(gen, 256*1024)
			if err != nil {
				return err
			}
			mux, err := NewAgentMuxConn(gc, DefaultMuxConfig())
			if err != nil {
				return err
			}
			mu.Lock()
			agentMux = mux
			mu.Unlock()
			serveAgent(context.Background(), mux, reg, Binding{HostID: "host-123", Epoch: 7}, target.ln.Addr().String())
			return nil
		case strings.HasPrefix(msg, "close:"):
			gen := uint32(msg[6] - '0')
			mu.Lock()
			m := agentMux
			agentMux = nil
			mu.Unlock()
			if m != nil {
				_ = m.Close()
			}
			d.Deactivate(gen)
			return nil
		}
		return nil
	}

	srvD, _, _, cliWS := demuxPair(t, nil, onAgentText)

	// 1) Activate gen=1 with 0-RTT text + binary.
	gc1, err := srvD.ActivateAndSendText(context.Background(), 1, 256*1024, []byte("open:1"))
	if err != nil {
		t.Fatal(err)
	}
	gw1, err := NewGatewayMuxConn(gc1, DefaultMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	s1, err := OpenSSHStream(context.Background(), gw1, req("s1", "a1"), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	bounce(t, s1, "gen1-ok")
	_ = s1.Close()

	// 2) Deactivate gen=1 (idle hibernation); outer WSS must remain alive.
	_ = srvD.SendText(context.Background(), []byte("close:1"))
	_ = gw1.Close()
	srvD.Deactivate(1)

	// Inject a late in-flight binary frame from retired gen=1: must be dropped,
	// not kill the WebSocket!
	late := make([]byte, 12)
	binary.BigEndian.PutUint32(late[:4], 1)
	copy(late[4:], []byte("stale-b!"))
	if err := cliWS.Write(context.Background(), websocket.MessageBinary, late); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// 3) Re-activate on gen=2 over the SAME WebSocket!
	gc2, err := srvD.ActivateAndSendText(context.Background(), 2, 256*1024, []byte("open:2"))
	if err != nil {
		t.Fatal(err)
	}
	gw2, err := NewGatewayMuxConn(gc2, DefaultMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer gw2.Close()
	s2, err := OpenSSHStream(context.Background(), gw2, req("s2", "a1"), 3*time.Second)
	if err != nil {
		t.Fatalf("gen2 stream failed after gen1 hibernation + stale frame: %v", err)
	}
	bounce(t, s2, "gen2-ok")
	_ = s2.Close()
}

// Negative tests: zero generation, future generation before mux.open, and
// short binary frames must all terminate the Demux loop.
func TestDemuxRejectsInvalidBinaryFrames(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
	}{
		{"too-short", []byte{0x01, 0x02}},
		{"zero-gen", []byte{0x00, 0x00, 0x00, 0x00, 'x'}},
		{"future-gen", []byte{0x00, 0x00, 0x00, 0x09, 'x'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runErr := make(chan error, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer ws.CloseNow()
				d := NewDemux(context.Background(), ws, 64*1024, 128*1024)
				runErr <- d.Run(func([]byte) error { return nil }, nil)
			}))
			defer srv.Close()
			cws, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cws.CloseNow()
			_ = cws.Write(context.Background(), websocket.MessageBinary, tc.frame)
			select {
			case err := <-runErr:
				if !errors.Is(err, ErrInvalidBinaryFrame) {
					t.Fatalf("got %v, want ErrInvalidBinaryFrame", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("demux did not reject invalid binary frame")
			}
		})
	}
}

func TestDemuxWriteBuffersReturnCountExcludesHeader(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		_, data, err := ws.Read(context.Background())
		if err == nil {
			got <- data
		}
	}))
	defer srv.Close()
	cws, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cws.CloseNow()
	d := NewDemux(context.Background(), cws, 64*1024, 128*1024)
	defer d.Close()
	gc, err := d.Activate(42, 64*1024)
	if err != nil {
		t.Fatal(err)
	}
	n, err := gc.WriteBuffers([][]byte{[]byte("hdr8byte"), []byte("payload!")})
	if err != nil {
		t.Fatal(err)
	}
	if n != 16 {
		t.Fatalf("WriteBuffers returned %d, want 16 (excluding 4B mux_gen)", n)
	}
	frame := <-got
	if len(frame) != 20 || binary.BigEndian.Uint32(frame[:4]) != 42 || string(frame[4:]) != "hdr8bytepayload!" {
		t.Fatalf("unexpected wire frame: %x", frame)
	}
	// Closing GenConn must only return io.ErrClosedPipe on future writes, not close ws.
	_ = gc.Close()
	if _, err := gc.Write([]byte("after")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after close: %v", err)
	}
}
