package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/agent"
	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/ca/catest"
	"github.com/indexyz/osmium/internal/devpki"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/server"
	"github.com/indexyz/osmium/internal/sessions"
)

const srvHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

type testFixture struct {
	store    *authz.Store
	hub      *agenthub.Hub
	mgr      *sessions.Manager
	auth     *authn.Authenticator
	web      *httptest.Server
	agentSrv *httptest.Server
	pki      *devpki.CA
}

func makePolicy(t *testing.T, disabledJSON string) *authz.Snapshot {
	t.Helper()
	if disabledJSON == "" {
		disabledJSON = "[]"
	}
	raw := `{"scope":"t1",
		"admins":[{"group":"admins"}],
		"disabled_users":` + disabledJSON + `,
		"hosts":[{"id":"host-123","allowed_login_users":["ops"],"ssh_host_keys":["` + srvHostKey + `"],"agent":{"id":"agent-123","client_cert_cn":"agent-123"}}],
		"grants":[{"id":"g1","subjects":[{"group":"ops"}],"hosts":{"ids":["host-123"]},"logins":["ops"]}]
	}`
	snap, err := authz.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func newFixture(t *testing.T, maxPending int) *testFixture {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fakeCA, err := catest.New("web-ssh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fakeCA.Close)
	caCfg, err := fakeCA.ClientConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ca.NewStepCA(caCfg)
	if err != nil {
		t.Fatal(err)
	}
	store := authz.NewStore(makePolicy(t, ""))
	hub := agenthub.New(agenthub.Config{MaxStreams: 8, MaxPendingStreams: maxPending, TicketTTL: 5 * time.Second}, store, nil, log)
	mgr := sessions.NewManager(sessions.Config{RevokeActive: true}, store, hub, signer, nil, log)
	auth, err := authn.New(context.Background(), authn.Config{DevLogin: true}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	store.OnChange(func(snap *authz.Snapshot) { auth.RevokeMatching(snap.IsDisabled) })
	srv := &server.Server{Store: store, Hub: hub, Sessions: mgr, Auth: auth, Log: log}
	web := httptest.NewServer(srv.WebHandler())
	srv.AllowedOrigins = []string{web.URL}
	t.Cleanup(web.Close)

	pki, err := devpki.NewCA("agent-ca")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pki.Issue("server", []string{"127.0.0.1"}, false)
	agentSrv := httptest.NewUnstartedServer(srv.AgentHandler())
	agentSrv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.TLS()}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.Pool()}
	agentSrv.StartTLS()
	t.Cleanup(agentSrv.Close)
	t.Cleanup(hub.Shutdown)

	return &testFixture{store: store, hub: hub, mgr: mgr, auth: auth, web: web, agentSrv: agentSrv, pki: pki}
}

func (f *testFixture) login(t *testing.T, user string, groups ...string) (*http.Client, string, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	q := "user=" + user
	for _, g := range groups {
		q += "&group=" + g
	}
	resp, err := c.Get(f.web.URL + "/auth/dev-login?" + q)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Get(f.web.URL + "/api/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var me struct {
		CSRF string `json:"csrf_token"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	return c, me.CSRF, me.User.ID
}

func (f *testFixture) issueCLIToken(t *testing.T, c *http.Client, csrf string) string {
	t.Helper()
	// Use standard PKCE flow via /auth/cli + /auth/cli/token.
	verifier := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	// S256 challenge via OAuth2 helper or direct request: let's compute via standard endpoints.
	// Since oauth2 is in go.mod, compute challenge cleanly:
	req, _ := http.NewRequest(http.MethodPost, f.web.URL+"/auth/cli",
		strings.NewReader("csrf="+csrf+"&port=43210&state=1234567890abcdef&code_challenge="+s256(verifier)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.web.URL)
	noRedir := *c
	noRedir.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedir.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	_, q, ok := strings.Cut(loc, "?")
	if !ok {
		t.Fatalf("missing redirect query: %q", loc)
	}
	var code string
	for _, part := range strings.Split(q, "&") {
		if k, v, _ := strings.Cut(part, "="); k == "code" {
			code = v
		}
	}
	body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
	resp, err = http.Post(f.web.URL+"/auth/cli/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.AccessToken
}

func s256(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestHealthzAndAdminRevocationAndDisabledUser(t *testing.T) {
	f := newFixture(t, 4)

	// /healthz requires no auth.
	resp, err := http.Get(f.web.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()

	aliceC, aliceCSRF, aliceID := f.login(t, "alice", "ops")
	adminC, adminCSRF, _ := f.login(t, "root", "admins")
	aliceTok := f.issueCLIToken(t, aliceC, aliceCSRF)

	// Non-admin cannot access admin token endpoints.
	if r, _ := aliceC.Get(f.web.URL + "/api/v1/admin/cli-tokens"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin list tokens: %d", r.StatusCode)
	}

	// Admin lists CLI tokens without exposing raw token.
	r, err := adminC.Get(f.web.URL + "/api/v1/admin/cli-tokens")
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("admin list tokens: %v", err)
	}
	rawBody, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if strings.Contains(string(rawBody), aliceTok) {
		t.Fatalf("admin endpoint exposed raw token")
	}
	var tokList struct {
		Items []authn.CLITokenInfo `json:"items"`
	}
	_ = json.Unmarshal(rawBody, &tokList)
	if len(tokList.Items) != 1 || tokList.Items[0].UserID != aliceID {
		t.Fatalf("unexpected token list: %+v", tokList.Items)
	}

	// Admin revokes CLI token by ID (requires CSRF).
	reqNoCSRF, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/admin/cli-tokens/"+tokList.Items[0].ID+"/revoke", nil)
	if r, _ := adminC.Do(reqNoCSRF); r.StatusCode != http.StatusForbidden {
		t.Fatalf("revoke without csrf: %d", r.StatusCode)
	}
	reqRevoke, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/admin/cli-tokens/"+tokList.Items[0].ID+"/revoke", nil)
	reqRevoke.Header.Set("X-CSRF-Token", adminCSRF)
	reqRevoke.Header.Set("Origin", f.web.URL)
	if r, _ := adminC.Do(reqRevoke); r.StatusCode != http.StatusOK {
		t.Fatalf("admin revoke token: %d", r.StatusCode)
	}
	// Revoked token is rejected immediately.
	reqMe, _ := http.NewRequest(http.MethodGet, f.web.URL+"/api/v1/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+aliceTok)
	if r, _ := http.DefaultClient.Do(reqMe); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token still accepted: %d", r.StatusCode)
	}

	// Issue a new CLI token for alice, then admin revokes the whole user.
	aliceTok2 := f.issueCLIToken(t, aliceC, aliceCSRF)
	reqUserRevoke, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/admin/users/"+aliceID+"/revoke", nil)
	reqUserRevoke.Header.Set("X-CSRF-Token", adminCSRF)
	reqUserRevoke.Header.Set("Origin", f.web.URL)
	if r, _ := adminC.Do(reqUserRevoke); r.StatusCode != http.StatusOK {
		t.Fatalf("admin user revoke: %d", r.StatusCode)
	}
	if r, _ := aliceC.Get(f.web.URL + "/api/v1/me"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("alice web session survived user revoke: %d", r.StatusCode)
	}
	reqMe2, _ := http.NewRequest(http.MethodGet, f.web.URL+"/api/v1/me", nil)
	reqMe2.Header.Set("Authorization", "Bearer "+aliceTok2)
	if r, _ := http.DefaultClient.Do(reqMe2); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("alice CLI token survived user revoke: %d", r.StatusCode)
	}

	// Policy reload disabling a user revokes their existing credentials immediately.
	bobC, bobCSRF, bobID := f.login(t, "bob", "ops")
	bobTok := f.issueCLIToken(t, bobC, bobCSRF)
	f.store.Replace(makePolicy(t, `[{"user_id":"`+bobID+`"}]`))
	if r, _ := bobC.Get(f.web.URL + "/api/v1/me"); r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled bob web session survived policy reload: %d", r.StatusCode)
	}
	reqBob, _ := http.NewRequest(http.MethodGet, f.web.URL+"/api/v1/me", nil)
	reqBob.Header.Set("Authorization", "Bearer "+bobTok)
	if r, _ := http.DefaultClient.Do(reqBob); r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled bob CLI token survived policy reload: %d", r.StatusCode)
	}
	// Even a freshly logged-in session for a disabled user is blocked with 403 USER_DISABLED.
	bobC2, _, _ := f.login(t, "bob", "ops")
	if r, _ := bobC2.Get(f.web.URL + "/api/v1/hosts"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled user got %d on /hosts, want 403", r.StatusCode)
	}
}

func TestMaxPendingStreamsAndNativeReadLimit(t *testing.T) {
	f := newFixture(t, 2) // MaxStreams=8, MaxPendingStreams=2

	// Start a dummy TCP listener standing in for sshd.
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
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()

	leaf, _ := f.pki.Issue("agent-123", nil, true)
	ready := make(chan uint64, 4)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.Run(ctx, agent.Options{
		ServerURL: "wss://" + f.agentSrv.Listener.Addr().String(),
		TLS:       &tls.Config{Certificates: []tls.Certificate{leaf.TLS()}, RootCAs: f.pki.Pool()},
		SSHTarget: ln.Addr().String(),
		Heartbeat: time.Second,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnReady:   func(ep uint64) { ready <- ep },
	})
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not become ready")
	}

	// 1) Verify MaxPendingStreams=2 blocks the 3rd unauthenticated stream, then allows after MarkAuthenticated.
	st1, err := f.hub.OpenStream(context.Background(), "host-123", "s1", "a1")
	if err != nil {
		t.Fatal(err)
	}
	defer st1.Close()
	st2, err := f.hub.OpenStream(context.Background(), "host-123", "s2", "a1")
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if _, err := f.hub.OpenStream(context.Background(), "host-123", "s3", "a1"); err != agenthub.ErrBusy {
		t.Fatalf("expected ErrBusy on 3rd pending stream, got %v", err)
	}
	st1.MarkAuthenticated()
	st3, err := f.hub.OpenStream(context.Background(), "host-123", "s3", "a2")
	if err != nil {
		t.Fatalf("expected 3rd stream after MarkAuthenticated, got %v", err)
	}
	defer st3.Close()
	st2.MarkAuthenticated()
	st3.MarkAuthenticated()

	// 2) Verify nativeTunnel enforces ReadLimit (oversized frame > 1 MiB closes tunnel instead of being ignored).
	aliceC, aliceCSRF, _ := f.login(t, "alice", "ops")
	tok := f.issueCLIToken(t, aliceC, aliceCSRF)

	// Cookie cannot create native session.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	keyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	reqCookie, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/native-sessions",
		strings.NewReader(`{"host_id":"host-123","login_user":"ops","public_key":"`+keyStr+`"}`))
	reqCookie.Header.Set("Content-Type", "application/json")
	reqCookie.Header.Set("X-CSRF-Token", aliceCSRF)
	reqCookie.Header.Set("Origin", f.web.URL)
	if r, _ := aliceC.Do(reqCookie); r.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie native create: %d, want 403", r.StatusCode)
	}

	// Bearer creates native session and opens /tunnel.
	reqBearer, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/native-sessions",
		strings.NewReader(`{"host_id":"host-123","login_user":"ops","public_key":"`+keyStr+`"}`))
	reqBearer.Header.Set("Content-Type", "application/json")
	reqBearer.Header.Set("Authorization", "Bearer "+tok)
	r, err := http.DefaultClient.Do(reqBearer)
	if err != nil || r.StatusCode != http.StatusCreated {
		t.Fatalf("bearer native create: %v %v", r, err)
	}
	var view sessions.View
	_ = json.NewDecoder(r.Body).Decode(&view)
	r.Body.Close()

	ws, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(f.web.URL, "http")+view.TunnelPath, &websocket.DialOptions{
		Subprotocols: []string{protocol.SubprotocolNative},
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + tok}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	// Wait for native.ready.
	for {
		_, data, err := ws.Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		m, err := protocol.DecodeNative(data)
		if err != nil {
			t.Fatal(err)
		}
		if m.Ready != nil {
			break
		}
	}
	// Send an oversized (> 1 MiB) binary frame: server must enforce ReadLimit and close.
	oversized := make([]byte, (1<<20)+4096)
	_ = ws.Write(context.Background(), websocket.MessageBinary, oversized)
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	for {
		_, _, err := ws.Read(rctx)
		if err != nil {
			if rctx.Err() != nil {
				t.Fatal("server did not close native tunnel after >1MiB frame")
			}
			break
		}
	}
}
