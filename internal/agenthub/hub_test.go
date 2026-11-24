package agenthub_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/indexyz/osmium/internal/agent"
	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/devpki"
	"github.com/indexyz/osmium/internal/protocol"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func buildPolicy(t *testing.T, n int) *authz.Snapshot {
	t.Helper()
	var hosts []string
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("host-%03d", i)
		ag := fmt.Sprintf("agent-%03d", i)
		hosts = append(hosts, fmt.Sprintf(`{"id":%q,"allowed_login_users":["ops"],"ssh_host_keys":[%q],"agent":{"id":%q,"client_cert_cn":%q}}`, id, testKey, ag, ag))
	}
	raw := fmt.Sprintf(`{"scope":"t1","hosts":[%s],"grants":[{"id":"g1","subjects":[{"group":"ops"}],"hosts":{"ids":["host-001"]},"logins":["ops"]}]}`, strings.Join(hosts, ","))
	snap, err := authz.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startHubServer(t *testing.T, cfg agenthub.Config, nHosts int) (*agenthub.Hub, *httptest.Server, *devpki.CA, *authz.Store) {
	t.Helper()
	store := authz.NewStore(buildPolicy(t, nHosts))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := agenthub.New(cfg, store, nil, log)
	t.Cleanup(func() {
		hub.Shutdown()
		hub.Wait(3 * time.Second)
	})
	pki, err := devpki.NewCA("agent-ca")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.Issue("server", []string{"127.0.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.TunnelPath, hub.HandleTunnel)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf.TLS()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.Pool(),
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return hub, srv, pki, store
}

// Verify that an idle Agent consumes zero smux sessions, activates smux on
// demand on OpenStream (gen=1), hibernates smux cleanly after MuxIdleTTL while
// keeping the WSS ready, and re-activates cleanly on gen=2.
func TestOnDemandMuxActivationAndIdleHibernation(t *testing.T) {
	hub, srv, pki, _ := startHubServer(t, agenthub.Config{
		PingInterval:     500 * time.Millisecond,
		HeartbeatTimeout: 2 * time.Second,
		MuxIdleTTL:       120 * time.Millisecond,
	}, 1)

	target := startEchoTCP(t)
	leaf, _ := pki.Issue("agent-001", nil, true)
	ready := make(chan uint64, 4)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.Run(ctx, agent.Options{
		ServerURL:       "wss://" + srv.Listener.Addr().String(),
		TLS:             &tls.Config{Certificates: []tls.Certificate{leaf.TLS()}, RootCAs: pki.Pool()},
		SSHTarget:       target,
		Heartbeat:       500 * time.Millisecond,
		ReconnectJitter: -1,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnReady:         func(ep uint64) { ready <- ep },
	})
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not register")
	}

	// 1) Idle: ready, but mux must NOT be active yet.
	agents := hub.Agents()
	if len(agents) != 1 || !agents[0].DataReady || agents[0].MuxActive {
		t.Fatalf("expected idle ready agent with mux_active=false, got %+v", agents)
	}

	// 2) First stream activates smux gen=1.
	st1, err := hub.OpenStream(context.Background(), "host-001", "s1", "a1")
	if err != nil {
		t.Fatal(err)
	}
	if st1.MuxGen != 1 {
		t.Fatalf("expected gen=1, got %d", st1.MuxGen)
	}
	agents = hub.Agents()
	if !agents[0].MuxActive || agents[0].Streams != 1 {
		t.Fatalf("expected mux_active=true streams=1, got %+v", agents[0])
	}
	if _, err := st1.Write([]byte("hello-1")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(st1, buf); err != nil || string(buf) != "hello-1" {
		t.Fatalf("echo 1: %q %v", buf, err)
	}
	_ = st1.Close()

	// 3) Wait past MuxIdleTTL: smux hibernates, but WSS epoch stays up & ready.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ag := hub.Agents()
		if len(ag) == 1 && !ag[0].MuxActive {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	ag := hub.Agents()
	if len(ag) != 1 || !ag[0].DataReady || ag[0].MuxActive {
		t.Fatalf("expected hibernated ready agent, got %+v", ag)
	}
	ep1 := ag[0].Epoch

	// 4) Second stream re-activates smux on gen=2 over the SAME WSS epoch.
	st2, err := hub.OpenStream(context.Background(), "host-001", "s2", "a1")
	if err != nil {
		t.Fatalf("re-activate gen=2 failed: %v", err)
	}
	defer st2.Close()
	if st2.Epoch != ep1 || st2.MuxGen != 2 {
		t.Fatalf("expected same epoch %d and gen=2, got epoch=%d gen=%d", ep1, st2.Epoch, st2.MuxGen)
	}
	if _, err := st2.Write([]byte("hello-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st2, buf); err != nil || string(buf) != "hello-2" {
		t.Fatalf("echo 2: %q %v", buf, err)
	}
}

// Verify sharded pagination, admission rate limiting (503), and background
// heartbeat reaper closing silent connections.
func TestShardedPaginationRateLimitAndReaper(t *testing.T) {
	// 1) Admission rate limit returns 503 when burst is exhausted.
	_, srvLim, pkiLim, _ := startHubServer(t, agenthub.Config{
		AcceptRate:  0.1,
		AcceptBurst: 1,
	}, 2)
	dialRaw := func(srv *httptest.Server, pki *devpki.CA, cn string) (*websocket.Conn, *http.Response, error) {
		leaf, _ := pki.Issue(cn, nil, true)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return websocket.Dial(ctx, "wss://"+srv.Listener.Addr().String()+protocol.TunnelPath, &websocket.DialOptions{
			HTTPClient:   &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{leaf.TLS()}, RootCAs: pki.Pool()}}},
			Subprotocols: []string{protocol.SubprotocolTunnel},
		})
	}
	c1, _, err := dialRaw(srvLim, pkiLim, "agent-001")
	if err != nil {
		t.Fatal(err)
	}
	defer c1.CloseNow()
	_, resp, err := dialRaw(srvLim, pkiLim, "agent-002")
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 rate limit, got resp=%v err=%v", resp, err)
	}

	// 2) Background heartbeat reaper closes silent agent automatically.
	hub, srv, pki, _ := startHubServer(t, agenthub.Config{
		PingInterval:     200 * time.Millisecond,
		HeartbeatTimeout: 450 * time.Millisecond,
	}, 6)
	silent, _, err := dialRaw(srv, pki, "agent-001")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.CloseNow()
	hello, _ := protocol.Encode(protocol.TypeHello, protocol.Hello{AgentVersion: "t", ReportedLabels: map[string]string{}})
	_ = silent.Write(context.Background(), websocket.MessageText, hello)
	_, _, _ = silent.Read(context.Background()) // welcome

	// Do not send any pings; reaper must terminate epoch within ~1s.
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, _, err = silent.Read(rctx)
	rcancel()
	if err == nil {
		t.Fatal("silent agent was not reaped after heartbeat timeout")
	}

	// 3) Connect 5 agents and verify cursor pagination + search filter.
	var conns []*websocket.Conn
	for i := 2; i <= 6; i++ {
		cn := fmt.Sprintf("agent-%03d", i)
		ws, _, err := dialRaw(srv, pki, cn)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, ws)
		_ = ws.Write(context.Background(), websocket.MessageText, hello)
		_, _, _ = ws.Read(context.Background())
	}
	defer func() {
		for _, ws := range conns {
			_ = ws.CloseNow()
		}
	}()

	p1 := hub.AgentsPage(agenthub.AgentsPageQuery{Limit: 2})
	if p1.Total != 5 || len(p1.Items) != 2 || p1.NextCursor == "" || p1.Items[0].AgentID != "agent-002" {
		t.Fatalf("page 1: %+v", p1)
	}
	p2 := hub.AgentsPage(agenthub.AgentsPageQuery{Limit: 2, Cursor: p1.NextCursor})
	if len(p2.Items) != 2 || p2.Items[0].AgentID != "agent-004" || p2.NextCursor == "" {
		t.Fatalf("page 2: %+v", p2)
	}
	p3 := hub.AgentsPage(agenthub.AgentsPageQuery{Limit: 2, Cursor: p2.NextCursor})
	if len(p3.Items) != 1 || p3.Items[0].AgentID != "agent-006" || p3.NextCursor != "" {
		t.Fatalf("page 3: %+v", p3)
	}
	filtered := hub.AgentsPage(agenthub.AgentsPageQuery{Query: "005", Limit: 10})
	if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].AgentID != "agent-005" {
		t.Fatalf("filtered: %+v", filtered)
	}
}
