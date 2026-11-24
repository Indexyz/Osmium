package client_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/ca/catest"
	"github.com/indexyz/osmium/internal/client"
	"github.com/indexyz/osmium/internal/server"
	"github.com/indexyz/osmium/internal/sessions"
)

const testHostCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

type clientEnv struct {
	api    *client.API
	auth   *authn.Authenticator
	store  *authz.Store
	fakeCA *catest.FakeCA
	web    *httptest.Server
	userID string
}

func newClientEnv(t *testing.T, defaultRoleTTL time.Duration) *clientEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fakeCA, err := catest.New("direct-ssh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fakeCA.Close)
	caCfg, err := fakeCA.ClientConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caCfg.MaxLifetime = 8*time.Hour + time.Minute
	caCfg.AllowedExts = []string{"permit-pty", "permit-user-rc", "permit-port-forwarding"}
	signer, err := ca.NewStepCA(caCfg)
	if err != nil {
		t.Fatal(err)
	}
	directIssuer, err := server.NewDirectCertIssuer(signer, server.DirectCertConfig{
		DefaultHostTTL: 60 * time.Second,
		DefaultRoleTTL: defaultRoleTTL,
		MaxRoleTTL:     8 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawPolicy := `{
		"scope": "t1",
		"admins": [{"group": "admins"}],
		"host_ca_public_keys": ["` + testHostCAKey + `"],
		"hosts": [
			{"id": "edge-db-1", "display_name": "edge-db-1", "connection_mode": "direct", "ssh_address": "10.0.2.15:2222", "allowed_login_users": ["ops"]},
			{"id": "tun-1", "display_name": "tun-1", "connection_mode": "tunnel", "allowed_login_users": ["ops"], "agent": {"id": "a1", "client_cert_cn": "a1"}}
		],
		"grants": [
			{"id": "g1", "subjects": [{"group": "ops"}], "hosts": {"ids": ["edge-db-1", "tun-1"]}, "logins": ["ops"]}
		],
		"cert_roles": [
			{"id": "r-ops", "subjects": [{"group": "ops"}], "principals": ["role:prod-ops", "team:sre"], "max_ttl": "4h"}
		]
	}`
	snap, err := authz.Parse(strings.NewReader(rawPolicy))
	if err != nil {
		t.Fatal(err)
	}
	store := authz.NewStore(snap)
	hub := agenthub.New(agenthub.Config{}, store, nil, log)
	t.Cleanup(hub.Shutdown)
	mgr := sessions.NewManager(sessions.Config{}, store, hub, signer, nil, log)
	t.Cleanup(mgr.Shutdown)
	auth, err := authn.New(context.Background(), authn.Config{DevLogin: true}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Shutdown)

	srv := &server.Server{Store: store, Hub: hub, Sessions: mgr, Direct: directIssuer, Auth: auth, Log: log}
	web := httptest.NewServer(srv.WebHandler())
	srv.AllowedOrigins = []string{web.URL}
	t.Cleanup(web.Close)

	// Log in alice and exchange for CLI Bearer token via PKCE.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	resp, err := hc.Get(web.URL + "/auth/dev-login?user=alice&group=ops")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = hc.Get(web.URL + "/api/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	var me struct {
		CSRF string `json:"csrf_token"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()

	verifier := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	req, _ := http.NewRequest(http.MethodPost, web.URL+"/auth/cli",
		strings.NewReader("csrf="+me.CSRF+"&port=43210&state=1234567890abcdef&code_challenge="+challenge))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", web.URL)
	noRedir := *hc
	noRedir.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err = noRedir.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	_, q, _ := strings.Cut(resp.Header.Get("Location"), "?")
	code := ""
	for _, part := range strings.Split(q, "&") {
		if k, v, _ := strings.Cut(part, "="); k == "code" {
			code = v
		}
	}
	tokBody, _ := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
	resp, err = http.Post(web.URL+"/auth/cli/token", "application/json", bytes.NewReader(tokBody))
	if err != nil {
		t.Fatal(err)
	}
	var tokOut struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokOut)
	resp.Body.Close()

	creds := &client.Credentials{
		Server:    web.URL,
		Token:     tokOut.AccessToken,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	creds.User.ID = me.User.ID
	api := &client.API{Creds: creds, HTTP: &http.Client{Timeout: 10 * time.Second}}
	return &clientEnv{api: api, auth: auth, store: store, fakeCA: fakeCA, web: web, userID: me.User.ID}
}

func TestBuiltinSSHAgentReadOnlyRotationAndRevocationWipe(t *testing.T) {
	// Short 3-second test certs so we observe live key-rotating renewal quickly.
	env := newClientEnv(t, 3*time.Second)
	env.fakeCA.Validity = 3 * time.Second

	// Keep the Unix socket path under the ~104-byte sockaddr_un limit.
	sockDir, err := os.MkdirTemp("", "oa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "a.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyCh := make(chan *ssh.Certificate, 1)
	renewCh := make(chan *ssh.Certificate, 4)
	wipeCh := make(chan string, 2)
	errCh := make(chan error, 1)

	go func() {
		errCh <- env.api.RunSSHAgent(ctx, client.SSHAgentOptions{
			SocketPath:    sockPath,
			RenewBefore:   2 * time.Second,
			CheckInterval: 100 * time.Millisecond,
			OnReady:       func(_ string, cert *ssh.Certificate) { readyCh <- cert },
			OnRenew:       func(cert *ssh.Certificate) { renewCh <- cert },
			OnWipe:        func(reason string) { wipeCh <- reason },
		})
	}()

	var initialCert *ssh.Certificate
	select {
	case initialCert = <-readyCh:
	case err := <-errCh:
		t.Fatalf("RunSSHAgent exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not become ready")
	}

	dialAgent := func() (agent.ExtendedAgent, func()) {
		c, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("dial unix socket %s: %v", sockPath, err)
		}
		return agent.NewClient(c), func() { _ = c.Close() }
	}

	// 1) OpenSSH agent client sees 1 signed certificate and can sign data verifiable by cert.Key.
	ag, closeAg := dialAgent()
	keys, err := ag.List()
	if err != nil || len(keys) != 1 {
		closeAg()
		t.Fatalf("agent.List: len=%d err=%v", len(keys), err)
	}
	pk, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		closeAg()
		t.Fatal(err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok || !bytes.Equal(cert.SignatureKey.Marshal(), env.fakeCA.UserCA.PublicKey().Marshal()) {
		closeAg()
		t.Fatalf("agent key is not a valid CA-signed cert: %T", pk)
	}
	payload := []byte("zero-trust-ssh-challenge")
	sig, err := ag.SignWithFlags(pk, payload, 0)
	if err != nil {
		closeAg()
		t.Fatalf("agent.SignWithFlags failed: %v", err)
	}
	if err := cert.Key.Verify(payload, sig); err != nil {
		closeAg()
		t.Fatalf("signature did not verify against cert key: %v", err)
	}

	// 2) Read-only guard: external Add/Remove/RemoveAll/Lock MUST fail.
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := ag.Add(agent.AddedKey{PrivateKey: roguePriv}); err == nil {
		t.Fatal("external Add succeeded on read-only osmium ssh-agent")
	}
	if err := ag.Remove(pk); err == nil {
		t.Fatal("external Remove succeeded on read-only osmium ssh-agent")
	}
	if err := ag.RemoveAll(); err == nil {
		t.Fatal("external RemoveAll succeeded on read-only osmium ssh-agent")
	}
	if err := ag.Lock([]byte("pw")); err == nil {
		t.Fatal("external Lock succeeded on read-only osmium ssh-agent")
	}
	closeAg()

	// 3) Automatic renewal rotates to a brand-new ephemeral public key.
	var renewedCert *ssh.Certificate
	select {
	case renewedCert = <-renewCh:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not auto-renew certificate")
	}
	if bytes.Equal(renewedCert.Key.Marshal(), initialCert.Key.Marshal()) {
		t.Fatal("renewal reused old ephemeral key instead of rotating")
	}

	// 4) Revoking the user's CLI token immediately wipes the agent's in-memory keys!
	env.auth.RevokeUser(env.userID)
	select {
	case reason := <-wipeCh:
		if reason != "credentials_revoked" && reason != "renewal_denied" {
			t.Fatalf("unexpected wipe reason: %q", reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not wipe keys after revocation")
	}
	ag2, closeAg2 := dialAgent()
	keysAfter, err := ag2.List()
	closeAg2()
	if err != nil || len(keysAfter) != 0 {
		t.Fatalf("keys survived revocation wipe: len=%d err=%v", len(keysAfter), err)
	}

	// 5) Shutdown cleanly removes the socket file.
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("RunSSHAgent shutdown err: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket file not removed after shutdown: %v", err)
	}
}

func TestIssueCertEnsureReuseAndGenerateSSHConfig(t *testing.T) {
	t.Setenv("OSMIUM_CONFIG", t.TempDir())
	env := newClientEnv(t, 4*time.Hour)
	ctx := context.Background()

	// 1) osmium cert ensure creates key + cert + known_hosts; second call reuses valid cert.
	outDir := filepath.Join(t.TempDir(), "host-cert")
	res1, err := env.api.IssueCert(ctx, client.CertOptions{
		Mode:         "host",
		HostID:       "edge-db-1",
		OutDir:       outDir,
		WriteKey:     true,
		ReuseValid:   true,
		MinRemaining: 20 * time.Second,
	})
	if err != nil || res1.Reused || res1.KeyPath == "" || res1.CertPath == "" || res1.KnownHostsPath == "" {
		t.Fatalf("first ensure failed: %+v err=%v", res1, err)
	}
	res2, err := env.api.IssueCert(ctx, client.CertOptions{
		Mode:         "host",
		HostID:       "edge-db-1",
		OutDir:       outDir,
		WriteKey:     true,
		ReuseValid:   true,
		MinRemaining: 20 * time.Second,
	})
	if err != nil || !res2.Reused {
		t.Fatalf("second ensure did not reuse valid cert: %+v err=%v", res2, err)
	}
	// Requesting higher MinRemaining forces fresh rotation with a new key!
	res3, err := env.api.IssueCert(ctx, client.CertOptions{
		Mode:         "host",
		HostID:       "edge-db-1",
		OutDir:       outDir,
		WriteKey:     true,
		ReuseValid:   true,
		MinRemaining: 2 * time.Minute,
	})
	if err != nil || res3.Reused || res3.CertID == res1.CertID {
		t.Fatalf("forced rotation did not issue fresh cert: %+v err=%v", res3, err)
	}

	// 2) GenerateSSHConfig (Match exec mode) writes Host CA known_hosts and includes direct host only.
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	cfg1, err := env.api.GenerateSSHConfig(ctx, client.SSHConfigOptions{
		KnownHostsPath: khPath,
		OsmiumBinary:   "/usr/local/bin/osmium",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Host edge-db-1", "HostName 10.0.2.15", "Port 2222", "User ops", "Match host edge-db-1 exec", "cert ensure --quiet", "StrictHostKeyChecking yes"} {
		if !strings.Contains(cfg1, want) {
			t.Fatalf("ssh-config missing %q:\n%s", want, cfg1)
		}
	}
	khBytes, err := os.ReadFile(khPath)
	if err != nil || !strings.Contains(string(khBytes), "@cert-authority * "+testHostCAKey) {
		t.Fatalf("known_hosts missing Host CA: %s %v", khBytes, err)
	}

	// 3) GenerateSSHConfig (--use-agent + --match-pattern).
	cfg2, err := env.api.GenerateSSHConfig(ctx, client.SSHConfigOptions{
		UseAgent:       true,
		AgentSocket:    "/tmp/osmium.sock",
		MatchPattern:   "*.prod.internal",
		KnownHostsPath: khPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Host *.prod.internal", "IdentityAgent /tmp/osmium.sock", "Host edge-db-1"} {
		if !strings.Contains(cfg2, want) {
			t.Fatalf("agent ssh-config missing %q:\n%s", want, cfg2)
		}
	}
}
