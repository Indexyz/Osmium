package sessions_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
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
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/ca/catest"
	"github.com/indexyz/osmium/internal/sessions"
	"github.com/indexyz/osmium/internal/tunnel"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func testStore(t *testing.T) *authz.Store {
	t.Helper()
	raw := `{"scope":"t1","hosts":[{"id":"host-123","allowed_login_users":["ops"],"ssh_host_keys":["` + testHostKey + `"],"agent":{"id":"agent-123","client_cert_cn":"agent-123"}}],"grants":[{"id":"g1","subjects":[{"user_id":"u-alice"}],"hosts":{"ids":["host-123"]},"logins":["ops"]}]}`
	snap, err := authz.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return authz.NewStore(snap)
}

func newKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

type mockOpener struct {
	open func(ctx context.Context) (*agenthub.Stream, error)
}

func (m *mockOpener) OpenStream(ctx context.Context, _, _, _ string) (*agenthub.Stream, error) {
	return m.open(ctx)
}

func (m *mockOpener) CloseAttempt(string, uint64, string, string, string) {}
func (m *mockOpener) Status(*authz.Host) string                           { return "ready" }

// smuxStreamPair creates a real smux v2 stream pair so CloseWrite() works as in production.
func smuxStreamPair(t *testing.T) (client *smux.Stream, server *smux.Stream) {
	t.Helper()
	got := make(chan *smux.Stream, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		mux, err := tunnel.NewAgentMux(context.Background(), ws, tunnel.DefaultMuxConfig())
		if err != nil {
			return
		}
		st, err := mux.AcceptStream()
		if err != nil {
			return
		}
		got <- st
		<-mux.CloseChan()
	}))
	t.Cleanup(srv.Close)
	ws, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := tunnel.NewGatewayMux(context.Background(), ws, tunnel.DefaultMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	c, err := gw.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	// Trigger stream frame delivery so AcceptStream unblocks.
	s := <-got
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, s
}

type fakeNativeClient struct {
	readyErr error
	pr       *io.PipeReader
	pw       *io.PipeWriter
	outMu    sync.Mutex
	out      bytes.Buffer
	readyCh  chan struct{}
}

func newFakeNativeClient(readyErr error) *fakeNativeClient {
	pr, pw := io.Pipe()
	return &fakeNativeClient{readyErr: readyErr, pr: pr, pw: pw, readyCh: make(chan struct{})}
}

func (c *fakeNativeClient) State(string) {}
func (c *fakeNativeClient) Ready(*ssh.Certificate, []ssh.PublicKey) error {
	close(c.readyCh)
	return c.readyErr
}
func (c *fakeNativeClient) CloseRead()                 { _ = c.pr.Close() }
func (c *fakeNativeClient) Read(p []byte) (int, error) { return c.pr.Read(p) }
func (c *fakeNativeClient) Write(p []byte) (int, error) {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	return c.out.Write(p)
}
func (c *fakeNativeClient) Output() string {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	return c.out.String()
}

type slowSigner struct {
	inner      ca.Signer
	delay      time.Duration
	inFlight   atomic.Int32
	maxInFlt   atomic.Int32
}

func (s *slowSigner) SignUserCert(ctx context.Context, r ca.Request) (*ssh.Certificate, error) {
	cur := s.inFlight.Add(1)
	for {
		prev := s.maxInFlt.Load()
		if cur <= prev || s.maxInFlt.CompareAndSwap(prev, cur) {
			break
		}
	}
	defer s.inFlight.Add(-1)
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.inner.SignUserCert(ctx, r)
}

func TestNativeReadyFailureMarksFailed(t *testing.T) {
	fakeCA, err := catest.New("web-ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeCA.Close()
	cfg, err := fakeCA.ClientConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ca.NewStepCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	opener := &mockOpener{open: func(context.Context) (*agenthub.Stream, error) {
		c, _ := smuxStreamPair(t)
		return &agenthub.Stream{Conn: c, HostID: "host-123", AgentID: "agent-123", Epoch: 1, StreamID: c.ID()}, nil
	}}
	mgr := sessions.NewManager(sessions.Config{}, testStore(t), opener, signer, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	alice := authz.Subject{UserID: "u-alice"}
	s, err := mgr.CreateNative(alice, sessions.NativeRequest{HostID: "host-123", Login: "ops", PublicKey: newKeyLine(t)})
	if err != nil {
		t.Fatal(err)
	}
	cl := newFakeNativeClient(errors.New("write broken"))
	if err := mgr.AttachNative(s, cl); err != nil {
		t.Fatal(err)
	}
	if s.State() != sessions.StateFailed {
		t.Fatalf("expected failed when Ready errors, got %s", s.State())
	}
}

func TestNativeHalfCloseDrainsRemoteTail(t *testing.T) {
	fakeCA, err := catest.New("web-ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeCA.Close()
	cfg, err := fakeCA.ClientConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ca.NewStepCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cStream, sStream := smuxStreamPair(t)
	go func() {
		defer sStream.Close()
		in, _ := io.ReadAll(sStream)
		time.Sleep(40 * time.Millisecond)
		_, _ = sStream.Write(append([]byte("tail:"), in...))
	}()
	opener := &mockOpener{open: func(context.Context) (*agenthub.Stream, error) {
		return &agenthub.Stream{Conn: cStream, HostID: "host-123", AgentID: "agent-123", Epoch: 1, StreamID: cStream.ID()}, nil
	}}
	mgr := sessions.NewManager(sessions.Config{}, testStore(t), opener, signer, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	alice := authz.Subject{UserID: "u-alice"}
	s, err := mgr.CreateNative(alice, sessions.NativeRequest{HostID: "host-123", Login: "ops", PublicKey: newKeyLine(t)})
	if err != nil {
		t.Fatal(err)
	}
	cl := newFakeNativeClient(nil)
	done := make(chan error, 1)
	go func() { done <- mgr.AttachNative(s, cl) }()
	<-cl.readyCh
	_, _ = cl.pw.Write([]byte("ping"))
	_ = cl.pw.Close() // clean client EOF → must trigger CloseWrite and drain "tail:ping"
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := cl.Output(); got != "tail:ping" {
		t.Fatalf("tail output truncated or lost: got %q, want %q", got, "tail:ping")
	}
}

func TestNativeIdleTimeoutClosesSession(t *testing.T) {
	fakeCA, err := catest.New("web-ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeCA.Close()
	cfg, err := fakeCA.ClientConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ca.NewStepCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cStream, _ := smuxStreamPair(t)
	opener := &mockOpener{open: func(context.Context) (*agenthub.Stream, error) {
		return &agenthub.Stream{Conn: cStream, HostID: "host-123", AgentID: "agent-123", Epoch: 1, StreamID: cStream.ID()}, nil
	}}
	mgr := sessions.NewManager(sessions.Config{IdleTimeout: 120 * time.Millisecond}, testStore(t), opener, signer, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	alice := authz.Subject{UserID: "u-alice"}
	s, err := mgr.CreateNative(alice, sessions.NativeRequest{HostID: "host-123", Login: "ops", PublicKey: newKeyLine(t)})
	if err != nil {
		t.Fatal(err)
	}
	cl := newFakeNativeClient(nil)
	if err := mgr.AttachNative(s, cl); err != nil {
		t.Fatal(err)
	}
	v := s.View()
	if v.EndReason == nil || *v.EndReason != "idle_timeout" {
		t.Fatalf("expected idle_timeout, got %+v", v.EndReason)
	}
}

func TestMaxConcurrentSignsBounded(t *testing.T) {
	fakeCA, err := catest.New("web-ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeCA.Close()
	cfg, err := fakeCA.ClientConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	baseSigner, err := ca.NewStepCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	slow := &slowSigner{inner: baseSigner, delay: 80 * time.Millisecond}
	opener := &mockOpener{open: func(context.Context) (*agenthub.Stream, error) {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		return &agenthub.Stream{Conn: a, HostID: "host-123", AgentID: "agent-123", Epoch: 1}, nil
	}}
	mgr := sessions.NewManager(sessions.Config{MaxConcurrentSigns: 2, MaxPerUser: 10}, testStore(t), opener, slow, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	alice := authz.Subject{UserID: "u-alice"}

	var wg sync.WaitGroup
	for range 5 {
		s, err := mgr.CreateNative(alice, sessions.NativeRequest{HostID: "host-123", Login: "ops", PublicKey: newKeyLine(t)})
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(sess *sessions.Session) {
			defer wg.Done()
			cl := newFakeNativeClient(errors.New("stop after sign"))
			_ = mgr.AttachNative(sess, cl)
		}(s)
	}
	wg.Wait()
	if got := slow.maxInFlt.Load(); got > 2 {
		t.Fatalf("concurrent CA signs exceeded limit: max=%d, want <=2", got)
	}
}
