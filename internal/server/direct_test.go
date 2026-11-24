package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/ca/catest"
	"github.com/indexyz/osmium/internal/server"
	"github.com/indexyz/osmium/internal/sessions"
)

func genEd25519Pub(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func makeDirectPolicy(t *testing.T, disabledJSON string) *authz.Snapshot {
	t.Helper()
	if disabledJSON == "" {
		disabledJSON = "[]"
	}
	raw := `{
		"scope": "t1",
		"admins": [{"group": "admins"}],
		"disabled_users": ` + disabledJSON + `,
		"host_ca_public_keys": ["` + srvHostKey + `"],
		"hosts": [
			{"id": "tunnel-1", "display_name": "tunnel-1", "connection_mode": "tunnel", "allowed_login_users": ["ops"], "ssh_host_keys": ["` + srvHostKey + `"], "agent": {"id": "agent-1", "client_cert_cn": "agent-1"}},
			{"id": "direct-1", "display_name": "direct-1", "connection_mode": "direct", "ssh_address": "10.0.2.15:22", "policy_labels": {"env": "prod"}, "allowed_login_users": ["ops", "deploy"], "ssh_host_keys": ["` + srvHostKey + `"]},
			{"id": "both-1", "display_name": "both-1", "connection_mode": "both", "ssh_address": "10.0.2.16:2222", "allowed_login_users": ["ops"], "agent": {"id": "agent-both", "client_cert_cn": "agent-both"}}
		],
		"grants": [
			{"id": "g-ops", "subjects": [{"group": "ops"}], "hosts": {"ids": ["tunnel-1", "direct-1", "both-1"]}, "logins": ["ops"]}
		],
		"cert_roles": [
			{"id": "r-ops", "subjects": [{"group": "ops"}], "principals": ["role:prod-ops", "team:sre"], "max_ttl": "2h", "extensions": ["permit-pty", "permit-port-forwarding"]}
		]
	}`
	snap, err := authz.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

type directFixture struct {
	*testFixture
	directCA *catest.FakeCA
	srv      *server.Server
}

func newDirectFixture(t *testing.T, directCfg server.DirectCertConfig) *directFixture {
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
	directIssuer, err := server.NewDirectCertIssuer(signer, directCfg)
	if err != nil {
		t.Fatal(err)
	}
	store := authz.NewStore(makeDirectPolicy(t, ""))
	hub := agenthub.New(agenthub.Config{MaxStreams: 8}, store, nil, log)
	t.Cleanup(hub.Shutdown)
	mgr := sessions.NewManager(sessions.Config{RevokeActive: true}, store, hub, signer, nil, log)
	t.Cleanup(mgr.Shutdown)
	auth, err := authn.New(context.Background(), authn.Config{DevLogin: true}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Shutdown)
	store.OnChange(func(snap *authz.Snapshot) { auth.RevokeMatching(snap.IsDisabled) })

	srv := &server.Server{Store: store, Hub: hub, Sessions: mgr, Direct: directIssuer, Auth: auth, Log: log}
	web := httptest.NewServer(srv.WebHandler())
	srv.AllowedOrigins = []string{web.URL}
	t.Cleanup(web.Close)

	return &directFixture{
		testFixture: &testFixture{store: store, hub: hub, mgr: mgr, auth: auth, web: web},
		directCA:    fakeCA,
		srv:         srv,
	}
}

func TestDirectCertsSecurityAndModes(t *testing.T) {
	f := newDirectFixture(t, server.DirectCertConfig{
		DefaultHostTTL: 60 * time.Second,
		DefaultRoleTTL: 4 * time.Hour,
		MaxRoleTTL:     8 * time.Hour,
	})
	aliceC, aliceCSRF, aliceID := f.login(t, "alice", "ops")
	adminC, adminCSRF, _ := f.login(t, "root", "admins")
	tok := f.issueCLIToken(t, aliceC, aliceCSRF)

	postDirect := func(bearer, body string, extraHeaders map[string]string) (*http.Response, []byte) {
		req, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/direct-certs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// 1) Browser cookie (even with CSRF & Origin) MUST be rejected with 403 BEARER_REQUIRED.
	pub1 := genEd25519Pub(t)
	reqCookie, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/direct-certs",
		strings.NewReader(`{"mode":"role","public_key":"`+pub1+`"}`))
	reqCookie.Header.Set("Content-Type", "application/json")
	reqCookie.Header.Set("X-CSRF-Token", aliceCSRF)
	reqCookie.Header.Set("Origin", f.web.URL)
	if r, _ := aliceC.Do(reqCookie); r.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie direct-certs: %d, want 403", r.StatusCode)
	}

	// 2) Unknown/client-supplied authority fields (source_address, extensions) rejected with 400.
	if r, _ := postDirect(tok, `{"mode":"role","source_address":"0.0.0.0/0","public_key":"`+pub1+`"}`, nil); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field source_address: %d, want 400", r.StatusCode)
	}

	// 3) Host mode on direct-1 succeeds, returns ssh_address, host_keys, host_cas, and exact single principal.
	r, b := postDirect(tok, `{"mode":"host","host_id":"direct-1","login_user":"ops","public_key":"`+pub1+`"}`, nil)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("host mode direct-1 failed: %d %s", r.StatusCode, b)
	}
	var hostResp struct {
		CertID      string    `json:"cert_id"`
		Certificate string    `json:"certificate"`
		Principals  []string  `json:"principals"`
		SSHAddress  string    `json:"ssh_address"`
		HostKeys    []string  `json:"host_keys"`
		HostCAs     []string  `json:"host_cas"`
		ValidBefore time.Time `json:"valid_before"`
	}
	_ = json.Unmarshal(b, &hostResp)
	if hostResp.SSHAddress != "10.0.2.15:22" || len(hostResp.Principals) != 1 || hostResp.Principals[0] != "tenant:t1:host:direct-1:login:ops" || len(hostResp.HostKeys) != 1 || len(hostResp.HostCAs) != 1 {
		t.Fatalf("unexpected host response: %+v", hostResp)
	}

	// 4) Reusing the same public key MUST fail with 400 KEY_REUSED.
	if r, b := postDirect(tok, `{"mode":"host","host_id":"direct-1","login_user":"ops","public_key":"`+pub1+`"}`, nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "KEY_REUSED") {
		t.Fatalf("reused key: %d %s", r.StatusCode, b)
	}

	// 5) Host mode on tunnel-only host or unauthorized login MUST fail with 403.
	if r, _ := postDirect(tok, `{"mode":"host","host_id":"tunnel-1","login_user":"ops","public_key":"`+genEd25519Pub(t)+`"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("tunnel-only host allowed direct cert: %d", r.StatusCode)
	}
	if r, _ := postDirect(tok, `{"mode":"host","host_id":"direct-1","login_user":"deploy","public_key":"`+genEd25519Pub(t)+`"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized login allowed direct cert: %d", r.StatusCode)
	}

	// 6) Web terminal session creation on direct-only host MUST fail with 503 HOST_UNAVAILABLE (no Server SSRF).
	reqWeb, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/v1/ssh-sessions",
		strings.NewReader(`{"host_id":"direct-1","login_user":"ops","terminal":{"rows":24,"cols":80}}`))
	reqWeb.Header.Set("Content-Type", "application/json")
	reqWeb.Header.Set("Idempotency-Key", "idem-direct-web")
	reqWeb.Header.Set("X-CSRF-Token", aliceCSRF)
	reqWeb.Header.Set("Origin", f.web.URL)
	if r, _ := aliceC.Do(reqWeb); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("web session on direct-only host: %d, want 503", r.StatusCode)
	}

	// 7) Role mode: TTL requested 24h is strictly capped to role's 2h max_ttl; unauthorized principal rejected.
	if r, _ := postDirect(tok, `{"mode":"role","principals":["role:prod-ops","root"],"public_key":"`+genEd25519Pub(t)+`"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized role principal accepted: %d", r.StatusCode)
	}
	r, b = postDirect(tok, `{"mode":"role","ttl":"24h","principals":["role:prod-ops"],"public_key":"`+genEd25519Pub(t)+`"}`, nil)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("role mode failed: %d %s", r.StatusCode, b)
	}
	var roleResp struct {
		Certificate string    `json:"certificate"`
		Principals  []string  `json:"principals"`
		ValidBefore time.Time `json:"valid_before"`
	}
	_ = json.Unmarshal(b, &roleResp)
	if len(roleResp.Principals) != 1 || roleResp.Principals[0] != "role:prod-ops" {
		t.Fatalf("unexpected role principals: %+v", roleResp.Principals)
	}
	if rem := time.Until(roleResp.ValidBefore); rem > 2*time.Hour+5*time.Second || rem < time.Hour+55*time.Minute {
		t.Fatalf("TTL not capped to role 2h: remaining=%s", rem)
	}

	// 8) GET /api/v1/hosts?status=direct & GET /api/v1/host-cas.
	rHosts, err := aliceC.Get(f.web.URL + "/api/v1/hosts?status=direct")
	if err != nil || rHosts.StatusCode != http.StatusOK {
		t.Fatalf("hosts?status=direct: %v %v", rHosts, err)
	}
	var hostPage struct {
		Items []struct {
			ID             string `json:"id"`
			ConnectionMode string `json:"connection_mode"`
			SSHAddress     string `json:"ssh_address"`
			Status         string `json:"status"`
		} `json:"items"`
	}
	_ = json.NewDecoder(rHosts.Body).Decode(&hostPage)
	rHosts.Body.Close()
	// Both direct-1 (direct) and both-1 (offline agent -> direct) show status=direct!
	if len(hostPage.Items) != 2 {
		t.Fatalf("expected 2 direct-status hosts, got %+v", hostPage.Items)
	}
	rCAs, err := aliceC.Get(f.web.URL + "/api/v1/host-cas")
	if err != nil || rCAs.StatusCode != http.StatusOK {
		t.Fatalf("host-cas: %v %v", rCAs, err)
	}
	var caResp struct {
		HostCAs []string `json:"host_ca_public_keys"`
	}
	_ = json.NewDecoder(rCAs.Body).Decode(&caResp)
	rCAs.Body.Close()
	if len(caResp.HostCAs) != 1 || caResp.HostCAs[0] != srvHostKey {
		t.Fatalf("unexpected host CAs: %+v", caResp.HostCAs)
	}

	// 9) Admin cert-roles CRUD requires admin + CSRF and takes effect immediately.
	reqNonAdmin, _ := http.NewRequest(http.MethodPut, f.web.URL+"/api/v1/admin/cert-roles/r-new",
		strings.NewReader(`{"subjects":[{"group":"ops"}],"principals":["role:new"]}`))
	reqNonAdmin.Header.Set("Content-Type", "application/json")
	reqNonAdmin.Header.Set("X-CSRF-Token", aliceCSRF)
	reqNonAdmin.Header.Set("Origin", f.web.URL)
	if r, _ := aliceC.Do(reqNonAdmin); r.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin upsert cert-role: %d", r.StatusCode)
	}
	reqAdminPut, _ := http.NewRequest(http.MethodPut, f.web.URL+"/api/v1/admin/cert-roles/r-new",
		strings.NewReader(`{"subjects":[{"group":"ops"}],"principals":["role:new"],"max_ttl":"1h"}`))
	reqAdminPut.Header.Set("Content-Type", "application/json")
	reqAdminPut.Header.Set("X-CSRF-Token", adminCSRF)
	reqAdminPut.Header.Set("Origin", f.web.URL)
	if r, _ := adminC.Do(reqAdminPut); r.StatusCode != http.StatusOK {
		t.Fatalf("admin upsert cert-role: %d", r.StatusCode)
	}
	if r, _ := postDirect(tok, `{"mode":"role","principals":["role:new"],"public_key":"`+genEd25519Pub(t)+`"}`, nil); r.StatusCode != http.StatusCreated {
		t.Fatalf("newly added cert-role not usable: %d", r.StatusCode)
	}
	reqAdminDel, _ := http.NewRequest(http.MethodDelete, f.web.URL+"/api/v1/admin/cert-roles/r-new", nil)
	reqAdminDel.Header.Set("X-CSRF-Token", adminCSRF)
	reqAdminDel.Header.Set("Origin", f.web.URL)
	if r, _ := adminC.Do(reqAdminDel); r.StatusCode != http.StatusOK {
		t.Fatalf("admin delete cert-role: %d", r.StatusCode)
	}

	// 10) Race condition: user disabled while CA is signing MUST discard cert and return 403 USER_DISABLED.
	f.directCA.SetDelay(200 * time.Millisecond)
	go func() {
		time.Sleep(50 * time.Millisecond)
		f.store.Replace(makeDirectPolicy(t, `[{"user_id":"`+aliceID+`"}]`))
	}()
	r, b = postDirect(tok, `{"mode":"role","public_key":"`+genEd25519Pub(t)+`"}`, nil)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "USER_DISABLED") {
		t.Fatalf("mid-sign user disable did not abort: %d %s", r.StatusCode, b)
	}
}

func TestDirectCertSourceAddressModesAndProxySpoofGuard(t *testing.T) {
	// A) Static CIDR mode.
	fStatic := newDirectFixture(t, server.DirectCertConfig{
		SourceAddressMode:  "static",
		SourceAddressCIDRs: "198.51.100.0/24, 10.20.0.0/16",
	})
	aliceC, aliceCSRF, _ := fStatic.login(t, "alice", "ops")
	tok := fStatic.issueCLIToken(t, aliceC, aliceCSRF)
	req, _ := http.NewRequest(http.MethodPost, fStatic.web.URL+"/api/v1/direct-certs",
		strings.NewReader(`{"mode":"role","public_key":"`+genEd25519Pub(t)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("static source-address failed: %v %v", resp, err)
	}
	var out struct {
		Certificate   string `json:"certificate"`
		SourceAddress string `json:"source_address"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.SourceAddress != "198.51.100.0/24,10.20.0.0/16" {
		t.Fatalf("static source_address=%q", out.SourceAddress)
	}
	pk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(out.Certificate))
	cert := pk.(*ssh.Certificate)
	if cert.CriticalOptions["source-address"] != "198.51.100.0/24,10.20.0.0/16" {
		t.Fatalf("cert critical options: %v", cert.CriticalOptions)
	}

	// B) client_ip mode WITHOUT trusted_proxies: spoofed X-Forwarded-For MUST be ignored.
	fUntrusted := newDirectFixture(t, server.DirectCertConfig{
		SourceAddressMode: "client_ip",
	})
	uC, uCSRF, _ := fUntrusted.login(t, "alice", "ops")
	uTok := fUntrusted.issueCLIToken(t, uC, uCSRF)
	req2, _ := http.NewRequest(http.MethodPost, fUntrusted.web.URL+"/api/v1/direct-certs",
		strings.NewReader(`{"mode":"role","public_key":"`+genEd25519Pub(t)+`"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+uTok)
	req2.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil || resp2.StatusCode != http.StatusCreated {
		t.Fatalf("client_ip untrusted failed: %v %v", resp2, err)
	}
	var out2 struct {
		SourceAddress string `json:"source_address"`
	}
	_ = json.NewDecoder(resp2.Body).Decode(&out2)
	resp2.Body.Close()
	if out2.SourceAddress != "127.0.0.1/32" && out2.SourceAddress != "::1/128" {
		t.Fatalf("spoofed X-Forwarded-For was honored without trusted_proxies: %q", out2.SourceAddress)
	}

	// C) client_ip mode WITH trusted_proxies=["127.0.0.1/32","::1/128"]: walks right-to-left, ignoring left-spoofed IP.
	fTrusted := newDirectFixture(t, server.DirectCertConfig{
		SourceAddressMode: "client_ip",
		TrustedProxies:    []string{"127.0.0.1/32", "::1/128", "10.0.0.0/8"},
	})
	tC, tCSRF, _ := fTrusted.login(t, "alice", "ops")
	tTok := fTrusted.issueCLIToken(t, tC, tCSRF)
	req3, _ := http.NewRequest(http.MethodPost, fTrusted.web.URL+"/api/v1/direct-certs",
		strings.NewReader(`{"mode":"role","public_key":"`+genEd25519Pub(t)+`"}`))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+tTok)
	req3.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.42, 10.0.0.5")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil || resp3.StatusCode != http.StatusCreated {
		t.Fatalf("client_ip trusted failed: %v %v", resp3, err)
	}
	var out3 struct {
		SourceAddress string `json:"source_address"`
	}
	_ = json.NewDecoder(resp3.Body).Decode(&out3)
	resp3.Body.Close()
	if out3.SourceAddress != "203.0.113.42/32" {
		t.Fatalf("expected rightmost non-proxy IP 203.0.113.42/32, got %q", out3.SourceAddress)
	}
}
