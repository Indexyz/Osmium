package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"
)

// pipePair builds a Gateway (client) and Agent (server) smux pair over a real
// WebSocket, matching production layering.
func pipePair(t *testing.T) (gw, ag *smux.Session, ws *websocket.Conn) {
	t.Helper()
	agentCh := make(chan *smux.Session, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"web-ssh-data.v1"}})
		if err != nil {
			return
		}
		mux, err := NewGatewayMux(context.Background(), c, DefaultMuxConfig())
		if err != nil {
			return
		}
		agentCh <- mux
		<-mux.CloseChan()
	}))
	t.Cleanup(srv.Close)
	c, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{Subprotocols: []string{"web-ssh-data.v1"}})
	if err != nil {
		t.Fatal(err)
	}
	ag, err = NewAgentMux(context.Background(), c, DefaultMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	gw = <-agentCh
	t.Cleanup(func() { gw.Close(); ag.Close() })
	return gw, ag, c
}

type echoTarget struct {
	ln    net.Listener
	dials atomic.Int32
}

func newEchoTarget(t *testing.T, banner string) *echoTarget {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &echoTarget{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.dials.Add(1)
			go func() {
				defer c.Close()
				if banner != "" {
					_, _ = c.Write([]byte(banner))
				}
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return e
}

func serveAgent(ctx context.Context, ag *smux.Session, reg *Registry, b Binding, target string) {
	go func() {
		for {
			st, err := ag.AcceptStream()
			if err != nil {
				return
			}
			if !reg.Reserve() {
				go RejectStream(st, CodeTooManyStreams, time.Second)
				continue
			}
			go func() {
				defer reg.Unreserve()
				_ = ServeSSHStream(ctx, st, AgentOptions{Binding: b, Target: target, OpenTimeout: 2 * time.Second, DialTimeout: time.Second, DrainTimeout: time.Second, Registry: reg})
			}()
		}
	}()
}

func req(session, attempt string) OpenRequest {
	return OpenRequest{Version: 1, Type: "ssh.open", HostID: "host-123", SessionID: session, AttemptID: attempt, Epoch: 7}
}

func bounce(t *testing.T, s net.Conn, msg string) {
	t.Helper()
	_ = s.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q want %q", buf, msg)
	}
	_ = s.SetDeadline(time.Time{})
}

// F01/F02/F06: two streams share one WebSocket; banner after ack is preserved;
// closing one stream leaves the other and the shared session alive.
func TestStreamsIsolatedOverSharedTunnel(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "SSH-2.0-test\r\n")
	reg := NewRegistry(32)
	serveAgent(context.Background(), ag, reg, Binding{"host-123", 7}, target.ln.Addr().String())
	ctx := context.Background()
	one, err := OpenSSHStream(ctx, gw, req("s1", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	two, err := OpenSSHStream(ctx, gw, req("s2", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []net.Conn{one, two} {
		bounceBanner := make([]byte, len("SSH-2.0-test\r\n"))
		_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(s, bounceBanner); err != nil || string(bounceBanner) != "SSH-2.0-test\r\n" {
			t.Fatalf("banner lost: %q %v", bounceBanner, err)
		}
	}
	bounce(t, one, "one")
	bounce(t, two, "two")
	_ = one.Close()
	bounce(t, two, "still-alive")
	if gw.IsClosed() || ag.IsClosed() {
		t.Fatal("closing one stream closed the shared session")
	}
	three, err := OpenSSHStream(ctx, gw, req("s3", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	banner := make([]byte, 14)
	if _, err := io.ReadFull(three, banner); err != nil {
		t.Fatal(err)
	}
	bounce(t, three, "three")
}

// C11/F09: write side half-close propagates and the reverse tail is drained.
func TestHalfCloseDrainsReply(t *testing.T) {
	gw, ag, _ := pipePair(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("reply:"), data...))
	}()
	serveAgent(context.Background(), ag, NewRegistry(4), Binding{"host-123", 7}, ln.Addr().String())
	s, err := OpenSSHStream(context.Background(), gw, req("s1", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = s.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err = s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply:payload" {
		t.Fatalf("bad reply %q", got)
	}
}

// F08/C05: wrong host or old epoch is refused before any dial.
func TestWrongBindingRejectedWithoutDial(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "")
	serveAgent(context.Background(), ag, NewRegistry(4), Binding{"host-123", 7}, target.ln.Addr().String())
	cases := map[string]OpenRequest{
		CodeHostMismatch: {Version: 1, Type: "ssh.open", HostID: "host-456", SessionID: "s1", AttemptID: "a1", Epoch: 7},
		CodeStaleEpoch:   {Version: 1, Type: "ssh.open", HostID: "host-123", SessionID: "s1", AttemptID: "a2", Epoch: 6},
	}
	for want, q := range cases {
		_, err := OpenSSHStream(context.Background(), gw, q, 2*time.Second)
		var rej *RejectedError
		if !errors.As(err, &rej) || rej.Code != want {
			t.Fatalf("want %s, got %v", want, err)
		}
	}
	if target.dials.Load() != 0 {
		t.Fatal("agent dialed for a rejected stream")
	}
}

// F13: replaying the same attempt is refused atomically.
func TestDuplicateAttemptRejected(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "")
	serveAgent(context.Background(), ag, NewRegistry(4), Binding{"host-123", 7}, target.ln.Addr().String())
	first, err := OpenSSHStream(context.Background(), gw, req("s1", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, err = OpenSSHStream(context.Background(), gw, req("s1", "a1"), 2*time.Second)
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Code != CodeDuplicateAttempt {
		t.Fatalf("want duplicate rejection, got %v", err)
	}
	bounce(t, first, "first-still-works")
}

// F12: streams beyond quota are refused; existing ones keep working.
func TestQuotaRejectsExtraStreams(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "")
	serveAgent(context.Background(), ag, NewRegistry(2), Binding{"host-123", 7}, target.ln.Addr().String())
	a, err := OpenSSHStream(context.Background(), gw, req("s1", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenSSHStream(context.Background(), gw, req("s2", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSSHStream(context.Background(), gw, req("s3", "a1"), 2*time.Second)
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Code != CodeTooManyStreams {
		t.Fatalf("want quota rejection, got %v", err)
	}
	bounce(t, a, "a")
	bounce(t, b, "b")
}

// Close before open leaves a tombstone; close during relay ends only that stream.
func TestRegistryCloseSemantics(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "")
	reg := NewRegistry(4)
	serveAgent(context.Background(), ag, reg, Binding{"host-123", 7}, target.ln.Addr().String())
	reg.Close("s1", "a1")
	_, err := OpenSSHStream(context.Background(), gw, req("s1", "a1"), 2*time.Second)
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Code != CodeCancelled {
		t.Fatalf("want cancelled, got %v", err)
	}
	live, err := OpenSSHStream(context.Background(), gw, req("s2", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other, err := OpenSSHStream(context.Background(), gw, req("s3", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reg.Close("s2", "a1")
	_ = live.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(live); err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed stream did not end: %v", err)
	}
	bounce(t, other, "unaffected")
}

// F07: a malformed prelude only kills its own stream.
func TestMalformedPreludeIsolated(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "")
	serveAgent(context.Background(), ag, NewRegistry(4), Binding{"host-123", 7}, target.ln.Addr().String())
	bad, err := gw.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = bad.Write([]byte{0xff, 0xff, 0xff, 0xff, 'x'})
	_ = bad.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(bad); err != nil && !strings.Contains(err.Error(), "closed") && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected: %v", err)
	}
	good, err := OpenSSHStream(context.Background(), gw, req("s1", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	bounce(t, good, "ok")
}

// F03: a stream whose ack never arrives times out alone.
func TestOpenTimeoutIsPerStream(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "")
	var mu sync.Mutex
	first := true
	reg := NewRegistry(4)
	go func() {
		for {
			st, err := ag.AcceptStream()
			if err != nil {
				return
			}
			mu.Lock()
			stall := first
			first = false
			mu.Unlock()
			if stall {
				continue // never answer; keep the stream open
			}
			reg.Reserve()
			go ServeSSHStream(context.Background(), st, AgentOptions{Binding: Binding{"host-123", 7}, Target: target.ln.Addr().String(), OpenTimeout: 2 * time.Second, DialTimeout: time.Second, DrainTimeout: time.Second, Registry: reg})
		}
	}()
	if _, err := OpenSSHStream(context.Background(), gw, req("s1", "a1"), 300*time.Millisecond); err == nil {
		t.Fatal("expected timeout")
	}
	if gw.IsClosed() {
		t.Fatal("timeout closed the shared session")
	}
	s, err := OpenSSHStream(context.Background(), gw, req("s2", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	bounce(t, s, "after-timeout")
}

// C06: a text frame on the data WebSocket is a protocol error for the tunnel.
func TestTextFrameKillsTunnel(t *testing.T) {
	gw, _, ws := pipePair(t)
	if err := ws.Write(context.Background(), websocket.MessageText, []byte(`{"type":"ssh.open"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gw.CloseChan():
	case <-time.After(3 * time.Second):
		t.Fatal("gateway accepted text frame on data tunnel")
	}
}

// F04: losing the tunnel ends every stream on it.
func TestTunnelLossEndsAllStreams(t *testing.T) {
	gw, ag, _ := pipePair(t)
	target := newEchoTarget(t, "")
	serveAgent(context.Background(), ag, NewRegistry(4), Binding{"host-123", 7}, target.ln.Addr().String())
	a, err := OpenSSHStream(context.Background(), gw, req("s1", "a1"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = ag.Close()
	_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := a.Read(buf); err == nil {
		t.Fatal("stream survived tunnel loss")
	}
}

func TestValidateTarget(t *testing.T) {
	for _, bad := range []string{"10.0.0.1:22", "localhost:22", "127.0.0.1:0", "[::1]:99999", "evil"} {
		if ValidateTarget(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, good := range []string{"127.0.0.1:22", "[::1]:2222"} {
		if err := ValidateTarget(good); err != nil {
			t.Fatalf("rejected %q: %v", good, err)
		}
	}
}
