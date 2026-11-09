package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/sessions"
	"github.com/indexyz/osmium/internal/sshgateway"
)

// A01 + F01/F02: two users share one Agent tunnel; closing one session leaves
// the other interactive; normal exit reports status.
func TestShellOverSharedTunnel(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	alice := e.signIn("alice")
	carol := e.signIn("carol")

	va, code := alice.create("host-123")
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	ta, err := alice.attach(va, e.web.URL)
	if err != nil {
		t.Fatal(err)
	}
	vc, _ := carol.create("host-123")
	tc, err := carol.attach(vc, e.web.URL)
	if err != nil {
		t.Fatal(err)
	}
	ta.waitActive()
	tc.waitActive()
	ta.roundTrip("alice1")
	tc.roundTrip("carol1")

	// Same tunnel: both attempts share epoch and data tunnel, distinct streams.
	sa, _ := e.mgr.Get(authz.Subject{UserID: alice.id}, va.ID)
	sc, _ := e.mgr.Get(authz.Subject{UserID: carol.id}, vc.ID)
	aa, ac := sa.View().Attempt, sc.View().Attempt
	if aa.Epoch != ac.Epoch || aa.DataTunnelID != ac.DataTunnelID || aa.StreamID == ac.StreamID {
		t.Fatalf("expected shared tunnel, distinct streams: %+v %+v", aa, ac)
	}
	if aa.CertSerial == ac.CertSerial || aa.PublicKeyFingerprint == ac.PublicKeyFingerprint || aa.CertKeyID == ac.CertKeyID {
		t.Fatal("attempts must use distinct keys and certificates (E06)")
	}
	if !strings.HasPrefix(aa.CertKeyID, "user:"+alice.id+"/session:"+va.ID) {
		t.Fatalf("key id %q", aa.CertKeyID)
	}

	if code := alice.post("/api/v1/ssh-sessions/"+va.ID+"/close", "", nil, nil); code != http.StatusAccepted {
		t.Fatalf("close: %d", code)
	}
	if x := ta.waitExit(); x.Reason != "user_close" {
		t.Fatalf("exit %+v", x)
	}
	tc.roundTrip("carol2")

	tc.send("exit\r")
	x := tc.waitExit()
	if x.Reason != "shell_exit" || x.ExitStatus == nil || *x.ExitStatus != 0 {
		t.Fatalf("exit %+v", x)
	}
	if st := sc.State(); st != sessions.StateClosed {
		t.Fatalf("state %s", st)
	}
}

// A02/A03/A04: Bob is refused until the server-side grant exists; adding it
// requires no change on the host; revoking Bob leaves Alice unaffected.
func TestDynamicGrantAndRevoke(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	bob := e.signIn("bob")
	alice := e.signIn("alice")
	if _, code := bob.create("host-123"); code != http.StatusForbidden {
		t.Fatalf("bob without grant: %d", code)
	}
	bobGrant := fmt.Sprintf(`{"id":"bob","subjects":[{"issuer":"dev","subject":"bob"}],"hosts":{"ids":["host-123"]},"logins":[%q]}`, e.login)
	e.store.Replace(e.policy([]string{bobGrant}, nil))

	vb, code := bob.create("host-123")
	if code != http.StatusCreated {
		t.Fatalf("bob with grant: %d", code)
	}
	tb, _ := bob.attach(vb, e.web.URL)
	tb.waitActive()
	tb.roundTrip("bob")
	va, _ := alice.create("host-123")
	ta, _ := alice.attach(va, e.web.URL)
	ta.waitActive()

	// D06: revoking Bob closes his active session; Alice keeps working.
	e.store.Replace(e.policy(nil, nil))
	if x := tb.waitExit(); x.Reason != "permission_revoked" {
		t.Fatalf("bob exit %+v", x)
	}
	ta.roundTrip("alice-after-revoke")
	if _, code := bob.create("host-123"); code != http.StatusForbidden {
		t.Fatalf("bob after revoke: %d", code)
	}
}

// A10/A11: Agent-reported labels never grant access; hidden hosts stay denied.
func TestVisibilityAndForgedLabels(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	e.startAgent("host-456")
	alice := e.signIn("alice")
	var hosts struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	getJSON(t, alice.c, e.web.URL+"/api/v1/hosts", &hosts)
	if len(hosts.Items) != 1 || hosts.Items[0].ID != "host-123" || hosts.Items[0].Status != "ready" {
		t.Fatalf("hosts %+v", hosts)
	}
	// host-456's agent reports env=prod, but policy labels say dev.
	if _, code := alice.create("host-456"); code != http.StatusForbidden {
		t.Fatalf("hidden host: %d", code)
	}
	getJSON(t, alice.c, e.web.URL+"/api/v1/hosts?label=env=dev", &hosts)
	if len(hosts.Items) != 0 {
		t.Fatal("filter widened visibility")
	}
	carol := e.signIn("carol")
	getJSON(t, carol.c, e.web.URL+"/api/v1/hosts?label=env=dev", &hosts)
	if len(hosts.Items) != 1 || hosts.Items[0].ID != "host-456" {
		t.Fatalf("carol filter %+v", hosts)
	}
}

// A05/A06: a valid certificate for host-123/login is refused by host-456 and
// for any other login on host-123.
func TestPrincipalBoundToHostAndLogin(t *testing.T) {
	e := newEnv(t)
	key, _ := sshgateway.NewEphemeralKey()
	cert, err := e.signer.SignUserCert(context.Background(), ca.Request{PublicKey: key.PublicKey(), KeyID: "user:test/session:x", Principal: authz.Principal("t1", "host-123", e.login)})
	if err != nil {
		t.Fatal(err)
	}
	try := func(hostID, login string) error {
		s := e.sshd[hostID]
		c, err := net.Dial("tcp", s.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		cl, err := sshgateway.Connect(context.Background(), c, sshgateway.Target{HostID: hostID, Login: login, HostKeys: []ssh.PublicKey{s.hostKey}}, key, cert, 5*time.Second)
		if err == nil {
			cl.Close()
		}
		return err
	}
	if err := try("host-123", e.login); err != nil {
		t.Fatalf("legit login failed: %v", err)
	}
	if err := try("host-456", e.login); err == nil {
		t.Fatal("certificate for host-123 accepted by host-456")
	}
	if err := try("host-123", "root"); err == nil {
		t.Fatal("certificate accepted for root")
	}
	// B04: within its validity the same cert can authenticate again; the
	// application must never reuse it (each attempt signs a new key).
	if err := try("host-123", e.login); err != nil {
		t.Fatalf("second use: %v", err)
	}
}

// C08: an unpinned host key fails closed.
func TestHostKeyMismatch(t *testing.T) {
	e := newEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewPublicKey(pub)
	e.store.Replace(e.policy(nil, map[string]string{"host-123": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other)))}))
	e.startAgent("host-123")
	alice := e.signIn("alice")
	v, _ := alice.create("host-123")
	tm, _ := alice.attach(v, e.web.URL)
	if x := tm.waitExit(); x.Reason != "host_key_mismatch" {
		t.Fatalf("exit %+v", x)
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, s := range tm.states {
		if s == sessions.StateActive {
			t.Fatal("session became active")
		}
	}
}

// B11: CA offline → no session, no fallback.
func TestCAOffline(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	e.fake.SetDown(true)
	alice := e.signIn("alice")
	v, _ := alice.create("host-123")
	tm, _ := alice.attach(v, e.web.URL)
	if x := tm.waitExit(); x.Reason != "ca_sign_failed" {
		t.Fatalf("exit %+v", x)
	}
	s, _ := e.mgr.Get(authz.Subject{UserID: alice.id}, v.ID)
	if s.State() != sessions.StateFailed {
		t.Fatalf("state %s", s.State())
	}
}

// D01/D02/D03/B07: ownership, Origin, idempotency and rejected extra fields.
func TestWebAPIGuards(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	alice := e.signIn("alice")
	carol := e.signIn("carol")

	body := map[string]any{"host_id": "host-123", "login_user": e.login, "terminal": map[string]int{"rows": 24, "cols": 80}}
	var v1, v2 sessions.View
	if code := alice.post("/api/v1/ssh-sessions", "same", body, &v1); code != http.StatusCreated {
		t.Fatalf("create %d", code)
	}
	if code := alice.post("/api/v1/ssh-sessions", "same", body, &v2); code != http.StatusOK || v2.ID != v1.ID {
		t.Fatalf("idempotent replay %d %s %s", code, v1.ID, v2.ID)
	}
	body2 := map[string]any{"host_id": "host-123", "login_user": e.login, "terminal": map[string]int{"rows": 30, "cols": 80}}
	if code := alice.post("/api/v1/ssh-sessions", "same", body2, nil); code != http.StatusConflict {
		t.Fatalf("idempotency conflict %d", code)
	}
	evil := map[string]any{"host_id": "host-123", "login_user": e.login, "terminal": map[string]int{"rows": 24, "cols": 80}, "principal": "tenant:t1:host:host-456:login:root"}
	if code := alice.post("/api/v1/ssh-sessions", nextIdem(), evil, nil); code != http.StatusBadRequest {
		t.Fatalf("extra field accepted %d", code)
	}
	// CSRF required.
	req, _ := http.NewRequest(http.MethodPost, e.web.URL+"/api/v1/ssh-sessions/"+v1.ID+"/close", nil)
	if resp, _ := alice.c.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("close without csrf %d", resp.StatusCode)
	}
	// Other users cannot see, attach or close.
	if code := getJSON(t, carol.c, e.web.URL+"/api/v1/ssh-sessions/"+v1.ID, nil); code != http.StatusNotFound {
		t.Fatalf("carol get %d", code)
	}
	if _, err := carol.attach(v1, e.web.URL); err == nil {
		t.Fatal("carol attached to alice's session")
	}
	if code := carol.post("/api/v1/ssh-sessions/"+v1.ID+"/close", "", nil, nil); code != http.StatusNotFound {
		t.Fatalf("carol close %d", code)
	}
	// Cross-site Origin refused.
	if _, err := alice.attach(v1, "https://evil.example"); err == nil {
		t.Fatal("foreign origin accepted")
	}
	// Owner attaches once; a second consumer is refused.
	tm, err := alice.attach(v1, e.web.URL)
	if err != nil {
		t.Fatal(err)
	}
	tm.waitActive()
	if _, err := alice.attach(v1, e.web.URL); err == nil {
		t.Fatal("second terminal consumer accepted")
	}
	// D05: invalid resize closes only this terminal with a policy error.
	_ = tm.ws.Write(context.Background(), websocket.MessageText, []byte(`{"version":1,"type":"terminal.resize","payload":{"rows":0,"cols":5}}`))
	if x := tm.waitExit(); x.Reason != "terminal_protocol_error" {
		t.Fatalf("exit after invalid resize: %+v", x)
	}
	// Admin can close others' sessions.
	v3, _ := carol.create("host-123")
	admin := e.signIn("root-admin", "admins")
	if code := admin.post("/api/v1/ssh-sessions/"+v3.ID+"/close", "", nil, nil); code != http.StatusAccepted {
		t.Fatalf("admin close %d", code)
	}
}

// F04/E01: losing the Agent ends its sessions; reconnect is a new epoch and
// only new sessions use it.
func TestAgentRestartNewEpoch(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	alice := e.signIn("alice")
	v, _ := alice.create("host-123")
	tm, _ := alice.attach(v, e.web.URL)
	tm.waitActive()
	s, _ := e.mgr.Get(authz.Subject{UserID: alice.id}, v.ID)
	oldEpoch := s.View().Attempt.Epoch

	e.stopAgent("host-123")
	if x := tm.waitExit(); x.Reason == "shell_exit" {
		t.Fatalf("unexpected clean exit %+v", x)
	}
	e.startAgent("host-123")
	v2, code := alice.create("host-123")
	if code != http.StatusCreated {
		t.Fatalf("create after restart %d", code)
	}
	tm2, _ := alice.attach(v2, e.web.URL)
	tm2.waitActive()
	s2, _ := e.mgr.Get(authz.Subject{UserID: alice.id}, v2.ID)
	if s2.View().Attempt.Epoch <= oldEpoch {
		t.Fatal("epoch did not advance")
	}
	tm2.roundTrip("new-epoch")
}

// C02/C03/C04: unauthenticated agents are refused; a data ticket is single
// use, bound to its agent, and concurrent replays succeed at most once.
func TestAgentRegistrationAndTicket(t *testing.T) {
	e := newEnv(t)
	addr := "wss://" + e.agentSrv.Listener.Addr().String()
	dial := func(cn, path, ticket string, sub string) (*websocket.Conn, *http.Response, error) {
		tlsCfg := e.agentTLS(cn)
		h := http.Header{}
		if ticket != "" {
			h.Set("Authorization", "Bearer "+ticket)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return websocket.Dial(ctx, addr+path, &websocket.DialOptions{HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}, Subprotocols: []string{sub}, HTTPHeader: h})
	}
	if _, resp, err := dial("agent-unknown", protocol.ControlPath, "", protocol.SubprotocolControl); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown agent: %v", err)
	}
	ctrl, _, err := dial("agent-123", protocol.ControlPath, "", protocol.SubprotocolControl)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.CloseNow()
	hello, _ := protocol.Encode(protocol.TypeHello, protocol.Hello{AgentVersion: "t", ReportedLabels: map[string]string{}})
	_ = ctrl.Write(context.Background(), websocket.MessageText, hello)
	_, data, err := ctrl.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, p, err := protocol.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	w := p.(*protocol.Welcome)
	// Another agent's identity cannot use this ticket (and burns it).
	if _, resp, err := dial("agent-456", protocol.DataPath, w.DataTicket, protocol.SubprotocolData); err == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatal("ticket accepted for a different agent identity")
	}
	// Fresh registration → fresh ticket; race two uses of it.
	ctrl.CloseNow()
	ctrl2, _, err := dial("agent-123", protocol.ControlPath, "", protocol.SubprotocolControl)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl2.CloseNow()
	_ = ctrl2.Write(context.Background(), websocket.MessageText, hello)
	_, data, _ = ctrl2.Read(context.Background())
	_, p, _ = protocol.Decode(data)
	w2 := p.(*protocol.Welcome)
	if w2.Epoch <= w.Epoch {
		t.Fatal("epoch did not advance")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, err := dial("agent-123", protocol.DataPath, w2.DataTicket, protocol.SubprotocolData)
			if err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
				t.Cleanup(func() { c.CloseNow() })
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("ticket used %d times", ok)
	}
	// Old epoch ticket is useless.
	if _, resp, err := dial("agent-123", protocol.DataPath, w.DataTicket, protocol.SubprotocolData); err == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatal("stale ticket accepted")
	}
}

// D07-style race: revocation between create and attach stops before signing.
func TestRevokeBeforeActivation(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	bobGrant := fmt.Sprintf(`{"id":"bob","subjects":[{"issuer":"dev","subject":"bob"}],"hosts":{"ids":["host-123"]},"logins":[%q]}`, e.login)
	e.store.Replace(e.policy([]string{bobGrant}, nil))
	bob := e.signIn("bob")
	v, code := bob.create("host-123")
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	issued := len(e.fake.Issued)
	e.store.Replace(e.policy(nil, nil))
	s, _ := e.mgr.Get(authz.Subject{UserID: bob.id}, v.ID)
	<-s.Done()
	if r := s.View().EndReason; r == nil || *r != "permission_revoked" {
		t.Fatalf("end reason %v", r)
	}
	if len(e.fake.Issued) != issued {
		t.Fatal("certificate issued after revocation")
	}
}
