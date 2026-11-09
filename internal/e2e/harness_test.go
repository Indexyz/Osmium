// Package e2e runs the whole system in-process against real OpenSSH sshd
// instances (unprivileged, loopback) and an in-process step-ca stand-in.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/agent"
	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/ca/catest"
	"github.com/indexyz/osmium/internal/devpki"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/server"
	"github.com/indexyz/osmium/internal/sessions"
)

type sshdInstance struct {
	hostID  string
	addr    string
	hostKey ssh.PublicKey
	cmd     *exec.Cmd
}

type env struct {
	t        *testing.T
	dir      string
	login    string
	fake     *catest.FakeCA
	signer   *ca.StepCA
	store    *authz.Store
	hub      *agenthub.Hub
	mgr      *sessions.Manager
	audit    *audit.Logger
	web      *httptest.Server
	agentSrv *httptest.Server
	pki      *devpki.CA
	sshd     map[string]*sshdInstance
	agents   map[string]context.CancelFunc
	ready    map[string]chan uint64
	mu       sync.Mutex
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writeHostKey(t *testing.T, path string) ssh.PublicKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return sp
}

func (e *env) startSSHD(hostID, scope string) *sshdInstance {
	t := e.t
	bin, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd not available")
	}
	bin, _ = filepath.EvalSymlinks(bin)
	d := filepath.Join(e.dir, "sshd-"+hostID)
	if err := os.MkdirAll(filepath.Join(d, "principals"), 0o755); err != nil {
		t.Fatal(err)
	}
	hk := writeHostKey(t, filepath.Join(d, "hostkey"))
	if err := os.WriteFile(filepath.Join(d, "user_ca.pub"), []byte(e.fake.UserCAAuthorizedKey()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "principals", e.login), []byte(authz.Principal(scope, hostID, e.login)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	host, port, _ := net.SplitHostPort(addr)
	conf := fmt.Sprintf(`Port %s
ListenAddress %s
HostKey %s/hostkey
PidFile %s/sshd.pid
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile none
TrustedUserCAKeys %s/user_ca.pub
AuthorizedPrincipalsFile %s/principals/%%u
LoginGraceTime 30
`, port, host, d, d, d, d)
	if err := os.WriteFile(filepath.Join(d, "sshd_config"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-D", "-e", "-f", filepath.Join(d, "sshd_config"))
	logf, _ := os.Create(filepath.Join(d, "sshd.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	s := &sshdInstance{hostID: hostID, addr: addr, hostKey: hk, cmd: cmd}
	e.sshd[hostID] = s
	return s
}

func newEnv(t *testing.T) *env {
	if testing.Short() {
		t.Skip("e2e skipped in -short mode")
	}
	u, err := user.Current()
	if err != nil || !authz.ValidLogin(u.Username) {
		t.Skip("current user name is not a valid login for the test")
	}
	e := &env{t: t, dir: t.TempDir(), login: u.Username, sshd: map[string]*sshdInstance{}, agents: map[string]context.CancelFunc{}, ready: map[string]chan uint64{}}
	e.fake, err = catest.New("web-ssh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.fake.Close)
	cfg, err := e.fake.ClientConfig(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if e.signer, err = ca.NewStepCA(cfg); err != nil {
		t.Fatal(err)
	}
	e.startSSHD("host-123", "t1")
	e.startSSHD("host-456", "t1")
	e.store = authz.NewStore(e.policy(nil, nil))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("E2E_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	var auditOut io.Writer = io.Discard
	if os.Getenv("E2E_LOG") != "" {
		auditOut = os.Stderr
	}
	e.audit = audit.New(auditOut)
	e.hub = agenthub.New(agenthub.Config{HeartbeatTimeout: 5 * time.Second, MaxStreams: 4}, e.store, e.audit, log)
	e.mgr = sessions.NewManager(sessions.Config{RevokeActive: true}, e.store, e.hub, e.signer, e.audit, log)
	auth, err := authn.New(context.Background(), authn.Config{DevLogin: true}, e.audit, log)
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Store: e.store, Hub: e.hub, Sessions: e.mgr, Auth: auth, Audit: e.audit, Log: log}
	e.web = httptest.NewServer(srv.WebHandler())
	srv.AllowedOrigins = []string{e.web.URL}
	t.Cleanup(e.web.Close)

	e.pki, err = devpki.NewCA("agent-ca")
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf, _ := e.pki.Issue("server", []string{"127.0.0.1"}, false)
	e.agentSrv = httptest.NewUnstartedServer(srv.AgentHandler())
	e.agentSrv.TLS = &tls.Config{Certificates: []tls.Certificate{serverLeaf.TLS()}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: e.pki.Pool()}
	e.agentSrv.StartTLS()
	t.Cleanup(e.agentSrv.Close)
	t.Cleanup(e.hub.Shutdown)
	return e
}

// policy builds a policy; grants maps user subject → logins on host-123.
func (e *env) policy(extraGrants []string, hostKeyOverride map[string]string) *authz.Snapshot {
	var hosts []string
	for _, id := range []string{"host-123", "host-456"} {
		s := e.sshd[id]
		key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.hostKey)))
		if o, ok := hostKeyOverride[id]; ok {
			key = o
		}
		env := map[string]string{"host-123": "prod", "host-456": "dev"}[id]
		hosts = append(hosts, fmt.Sprintf(`{"id":%q,"policy_labels":{"env":%q},"allowed_login_users":[%q],"ssh_host_keys":[%q],"agent":{"id":"agent-%s","client_cert_cn":"agent-%s"}}`,
			id, env, e.login, key, strings.TrimPrefix(id, "host-"), strings.TrimPrefix(id, "host-")))
	}
	grants := append([]string{fmt.Sprintf(`{"id":"alice","subjects":[{"issuer":"dev","subject":"alice"}],"hosts":{"labels":{"env":"prod"}},"logins":[%q]}`, e.login),
		fmt.Sprintf(`{"id":"carol","subjects":[{"issuer":"dev","subject":"carol"}],"hosts":{"ids":["host-123","host-456"]},"logins":[%q]}`, e.login)}, extraGrants...)
	doc := fmt.Sprintf(`{"scope":"t1","admins":[{"group":"admins"}],"hosts":[%s],"grants":[%s]}`, strings.Join(hosts, ","), strings.Join(grants, ","))
	s, err := authz.Parse(strings.NewReader(doc))
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) agentTLS(cn string) *tls.Config {
	leaf, err := e.pki.Issue(cn, nil, true)
	if err != nil {
		e.t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{leaf.TLS()}, RootCAs: e.pki.Pool()}
}

func (e *env) startAgent(hostID string) {
	ctx, cancel := context.WithCancel(context.Background())
	n := strings.TrimPrefix(hostID, "host-")
	ready := make(chan uint64, 16)
	e.mu.Lock()
	e.agents[hostID] = cancel
	e.ready[hostID] = ready
	e.mu.Unlock()
	e.t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go agent.Run(ctx, agent.Options{
		ServerURL: "wss://" + e.agentSrv.Listener.Addr().String(), TLS: e.agentTLS("agent-" + n), SSHTarget: e.sshd[hostID].addr,
		Labels: map[string]string{"env": "prod", "role": "forged"}, Version: "test", Heartbeat: time.Second, Log: log,
		OnReady: func(ep uint64) { ready <- ep },
	})
	e.waitReady(hostID)
}

func (e *env) waitReady(hostID string) uint64 {
	e.mu.Lock()
	ch := e.ready[hostID]
	e.mu.Unlock()
	select {
	case ep := <-ch:
		host, _ := e.store.Current().Host(hostID)
		for i := 0; i < 100 && e.hub.Status(host) != "ready"; i++ {
			time.Sleep(20 * time.Millisecond)
		}
		return ep
	case <-time.After(10 * time.Second):
		e.t.Fatalf("agent for %s not ready", hostID)
	}
	return 0
}

func (e *env) stopAgent(hostID string) {
	e.mu.Lock()
	cancel := e.agents[hostID]
	e.mu.Unlock()
	cancel()
}

// browser is a logged-in Web user.
type browser struct {
	e    *env
	c    *http.Client
	csrf string
	id   string
}

func (e *env) signIn(name string, groups ...string) *browser {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	q := "user=" + name
	for _, g := range groups {
		q += "&group=" + g
	}
	resp, err := c.Get(e.web.URL + "/auth/dev-login?" + q)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	var me struct {
		CSRF string     `json:"csrf_token"`
		User authn.User `json:"user"`
	}
	if code := getJSON(e.t, c, e.web.URL+"/api/v1/me", &me); code != 200 {
		e.t.Fatalf("me: %d", code)
	}
	return &browser{e: e, c: c, csrf: me.CSRF, id: me.User.ID}
}

func getJSON(t *testing.T, c *http.Client, url string, dst any) int {
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if dst != nil {
		_ = json.NewDecoder(resp.Body).Decode(dst)
	}
	return resp.StatusCode
}

func (b *browser) post(path, idem string, body any, dst any) int {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req, _ := http.NewRequest(http.MethodPost, b.e.web.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", b.csrf)
	req.Header.Set("Origin", b.e.web.URL)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if dst != nil {
		_ = json.NewDecoder(resp.Body).Decode(dst)
	}
	return resp.StatusCode
}

var idemCounter struct {
	sync.Mutex
	n int
}

func nextIdem() string {
	idemCounter.Lock()
	defer idemCounter.Unlock()
	idemCounter.n++
	return fmt.Sprintf("k-%d-%d", time.Now().UnixNano(), idemCounter.n)
}

func (b *browser) create(hostID string) (sessions.View, int) {
	var v sessions.View
	code := b.post("/api/v1/ssh-sessions", nextIdem(), map[string]any{"host_id": hostID, "login_user": b.e.login, "terminal": map[string]int{"rows": 24, "cols": 80}}, &v)
	return v, code
}

// term is a browser terminal WebSocket client.
type term struct {
	t      *testing.T
	ws     *websocket.Conn
	mu     sync.Mutex
	out    bytes.Buffer
	states []string
	exit   *protocol.TermExit
	closed chan struct{}
}

func (b *browser) attach(v sessions.View, origin string) (*term, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(b.e.web.URL, "http")+v.TermPath, &websocket.DialOptions{
		HTTPClient: b.c, Subprotocols: []string{protocol.SubprotocolTerminal}, HTTPHeader: http.Header{"Origin": []string{origin}},
	})
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(1 << 20)
	tm := &term{t: b.e.t, ws: ws, closed: make(chan struct{})}
	go func() {
		defer close(tm.closed)
		for {
			typ, data, err := ws.Read(context.Background())
			if err != nil {
				return
			}
			tm.mu.Lock()
			if typ == websocket.MessageBinary {
				tm.out.Write(data)
			} else {
				var env struct {
					Type    string          `json:"type"`
					Payload json.RawMessage `json:"payload"`
				}
				_ = json.Unmarshal(data, &env)
				switch env.Type {
				case protocol.TypeTermState:
					var s protocol.TermState
					_ = json.Unmarshal(env.Payload, &s)
					tm.states = append(tm.states, s.State)
				case protocol.TypeTermExit:
					var x protocol.TermExit
					_ = json.Unmarshal(env.Payload, &x)
					tm.exit = &x
				}
			}
			tm.mu.Unlock()
		}
	}()
	b.e.t.Cleanup(func() { ws.CloseNow() })
	return tm, nil
}

func (tm *term) waitFor(desc string, cond func() bool, timeout time.Duration) {
	tm.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		tm.mu.Lock()
		ok := cond()
		tm.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.t.Fatalf("timeout waiting for %s; states=%v exit=%+v output=%q", desc, tm.states, tm.exit, tm.out.String())
}

func (tm *term) waitActive() {
	tm.t.Helper()
	tm.waitFor("active", func() bool {
		for _, s := range tm.states {
			if s == sessions.StateActive {
				return true
			}
		}
		return tm.exit != nil
	}, 20*time.Second)
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.exit != nil {
		tm.t.Fatalf("session ended before active: %+v states=%v", tm.exit, tm.states)
	}
}

func (tm *term) waitExit() *protocol.TermExit {
	tm.t.Helper()
	tm.waitFor("exit", func() bool { return tm.exit != nil }, 20*time.Second)
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.exit
}

func (tm *term) send(s string) {
	if err := tm.ws.Write(context.Background(), websocket.MessageBinary, []byte(s)); err != nil {
		tm.t.Fatal(err)
	}
}

// roundTrip runs a printf whose output differs from its echoed input.
func (tm *term) roundTrip(marker string) {
	tm.t.Helper()
	tm.send(fmt.Sprintf("printf 'mk-%%s-%%s\\n' %s done\r", marker))
	want := "mk-" + marker + "-done"
	tm.waitFor("output "+want, func() bool { return strings.Contains(tm.out.String(), want) }, 15*time.Second)
}
