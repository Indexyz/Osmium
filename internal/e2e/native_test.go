package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/sessions"
)

var buildOnce struct {
	sync.Once
	path string
	err  error
}

// osmiumBinary builds cmd/osmium once per test process.
func osmiumBinary(t *testing.T) string {
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "osmium-e2e-bin-")
		if err != nil {
			buildOnce.err = err
			return
		}
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Join(filepath.Dir(file), "..", "..")
		buildOnce.path = filepath.Join(dir, "osmium")
		cmd := exec.Command("go", "build", "-o", buildOnce.path, "./cmd/osmium")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			buildOnce.err = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if buildOnce.err != nil {
		t.Fatal(buildOnce.err)
	}
	return buildOnce.path
}

// cli is one user's osmium CLI environment.
type cli struct {
	t    *testing.T
	e    *env
	bin  string
	envv []string
	sock string // ssh-agent socket
}

func (e *env) newCLI(t *testing.T) *cli {
	for _, b := range []string{"ssh", "ssh-agent", "ssh-add"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not available", b)
		}
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	agentCmd := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := agentCmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agentCmd.Process.Kill(); _ = agentCmd.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Isolate from the developer's ~/.ssh: HOME points at an empty dir.
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "OSMIUM_CONFIG=" + filepath.Join(dir, "cfg"), "SSH_AUTH_SOCK=" + sock, "TMPDIR=" + os.TempDir()}
	return &cli{t: t, e: e, bin: osmiumBinary(t), envv: env, sock: sock}
}

func (c *cli) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Env = c.envv
	return cmd
}

var csrfRe = regexp.MustCompile(`name="(csrf|port|state|code_challenge)" value="([^"]*)"`)

// login runs `osmium login` and approves it in b's browser session.
func (c *cli) login(b *browser) {
	t := c.t
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := c.command(ctx, "login", "--server", c.e.web.URL, "--no-browser")
	stderr, _ := cmd.StderrPipe()
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var authURL string
	sc := bufio.NewScanner(stderr)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); strings.HasPrefix(l, c.e.web.URL+"/auth/cli?") {
			authURL = l
			break
		}
	}
	go io.Copy(io.Discard, stderr)
	if authURL == "" {
		t.Fatal("login URL not printed")
	}
	// The browser shows the confirmation page...
	resp, err := b.c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := url.Values{}
	for _, m := range csrfRe.FindAllStringSubmatch(string(page), -1) {
		form.Set(m[1], m[2])
	}
	if form.Get("csrf") == "" {
		t.Fatalf("confirmation page without form: %s", page)
	}
	// ...and the user approves. Redirects are not followed by the API client,
	// so the loopback callback is visited explicitly.
	noRedirect := *b.c
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequest(http.MethodPost, c.e.web.URL+"/auth/cli", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", c.e.web.URL)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "http://127.0.0.1:") {
		t.Fatalf("approve: %d %q", resp.StatusCode, loc)
	}
	resp, err = http.Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("osmium login: %v", err)
	}
	if !strings.Contains(stdout.String(), "已登录") {
		t.Fatalf("login output %q", stdout.String())
	}
}

func (c *cli) run(timeout time.Duration, args ...string) (stdout, stderr string, code int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := c.command(ctx, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		c.t.Fatal(err)
	}
	return o.String(), e.String(), code
}

func (c *cli) agentKeys() string {
	cmd := exec.Command("ssh-add", "-l")
	cmd.Env = c.envv
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func (c *cli) token() string {
	b, err := os.ReadFile(filepath.Join(strings.TrimPrefix(c.envv[2], "OSMIUM_CONFIG="), "credentials.json"))
	if err != nil {
		c.t.Fatal(err)
	}
	m := regexp.MustCompile(`"access_token": "([^"]+)"`).FindStringSubmatch(string(b))
	if m == nil {
		c.t.Fatal("no token stored")
	}
	return m[1]
}

// Native OpenSSH client: login, list, connect via ssh-agent, exit codes,
// strict host keys, and agent cleanup.
func TestNativeSSHClient(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	c := e.newCLI(t)
	alice := e.signIn("alice")
	c.login(alice)

	out, errOut, code := c.run(20*time.Second, "hosts")
	if code != 0 || !strings.Contains(out, "host-123") || strings.Contains(out, "host-456") {
		t.Fatalf("hosts: %d %q %q", code, out, errOut)
	}

	out, errOut, code = c.run(30*time.Second, "ssh", "-v", "host-123", "printf", "native-%s\\n", "42")
	if code != 0 || !strings.Contains(out, "native-42") {
		t.Fatalf("ssh: code=%d out=%q err=%q", code, out, errOut)
	}
	if !strings.Contains(errOut, "ssh-agent") {
		t.Fatalf("expected ssh-agent path, stderr=%q", errOut)
	}
	if k := c.agentKeys(); !strings.Contains(k, "no identities") {
		t.Fatalf("ssh-agent still holds keys: %q", k)
	}

	// Remote exit status propagates.
	_, _, code = c.run(30*time.Second, "ssh", e.login+"@host-123", "exit 7")
	if code != 7 {
		t.Fatalf("exit code %d", code)
	}

	// Without ssh-agent.
	out, errOut, code = c.run(30*time.Second, "ssh", "--no-agent", "host-123", "echo", "no-agent-ok")
	if code != 0 || !strings.Contains(out, "no-agent-ok") {
		t.Fatalf("no-agent: %d %q %q", code, out, errOut)
	}

	// Not authorized for host-456.
	_, errOut, code = c.run(20*time.Second, "ssh", e.login+"@host-456", "true")
	if code == 0 || !strings.Contains(errOut, "not allowed") {
		t.Fatalf("host-456: %d %q", code, errOut)
	}

	// Sessions are recorded as native, with distinct keys per attempt.
	admin := authz.Subject{UserID: alice.id, IsAdmin: true}
	fps := map[string]bool{}
	n := 0
	for _, v := range e.mgr.List(admin) {
		if v.Mode != sessions.ModeNative || v.Attempt == nil {
			continue
		}
		n++
		if fps[v.Attempt.PublicKeyFingerprint] {
			t.Fatal("key reused across attempts")
		}
		fps[v.Attempt.PublicKeyFingerprint] = true
		if v.State != sessions.StateClosed {
			t.Fatalf("session %s state %s", v.ID, v.State)
		}
	}
	if n != 3 {
		t.Fatalf("native sessions %d", n)
	}

	// Logout revokes the token server-side.
	tok := c.token()
	if _, _, code = c.run(10*time.Second, "logout"); code != 0 {
		t.Fatal("logout failed")
	}
	req, _ := http.NewRequest(http.MethodGet, e.web.URL+"/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", resp.StatusCode)
	}
}

// A pinned host key that does not match makes OpenSSH refuse.
func TestNativeHostKeyMismatch(t *testing.T) {
	e := newEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewPublicKey(pub)
	e.store.Replace(e.policy(nil, map[string]string{"host-123": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other)))}))
	e.startAgent("host-123")
	c := e.newCLI(t)
	c.login(e.signIn("alice"))
	out, errOut, code := c.run(30*time.Second, "ssh", "host-123", "echo", "should-not-run")
	if code == 0 || strings.Contains(out, "should-not-run") || !strings.Contains(strings.ToLower(errOut), "host key") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}

// Revocation closes an active native session.
func TestNativeRevoke(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	bobGrant := fmt.Sprintf(`{"id":"bob","subjects":[{"issuer":"dev","subject":"bob"}],"hosts":{"ids":["host-123"]},"logins":[%q]}`, e.login)
	e.store.Replace(e.policy([]string{bobGrant}, nil))
	c := e.newCLI(t)
	bob := e.signIn("bob")
	c.login(bob)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := c.command(ctx, "ssh", "host-123", "sleep", "60")
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	subj := authz.Subject{UserID: bob.id}
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		for _, v := range e.mgr.List(subj) {
			if v.State == sessions.StateActive {
				id = v.ID
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if id == "" {
		t.Fatalf("native session never active: %s", errOut.String())
	}
	time.Sleep(500 * time.Millisecond) // let sshd start the command
	start := time.Now()
	e.store.Replace(e.policy(nil, nil))
	err := cmd.Wait()
	if err == nil || time.Since(start) > 15*time.Second {
		t.Fatalf("ssh did not end after revoke: err=%v after %s", err, time.Since(start))
	}
	s, _ := e.mgr.Get(subj, id)
	if r := s.View().EndReason; r == nil || *r != "permission_revoked" {
		t.Fatalf("end reason %v", *r)
	}
	if !strings.Contains(errOut.String(), "permission_revoked") {
		t.Logf("stderr: %s", errOut.String())
	}
}

// API guards for native sessions.
func TestNativeAPIGuards(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	c := e.newCLI(t)
	alice := e.signIn("alice")
	c.login(alice)
	tok := c.token()

	call := func(body string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, e.web.URL+"/api/v1/native-sessions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	ok := fmt.Sprintf(`{"host_id":"host-123","login_user":%q,"public_key":%q}`, e.login, key)
	if code, b := call(ok); code != http.StatusCreated {
		t.Fatalf("create %d %s", code, b)
	}
	if code, b := call(ok); code != http.StatusBadRequest || !strings.Contains(b, "KEY_REUSED") {
		t.Fatalf("reuse %d %s", code, b)
	}
	if code, _ := call(fmt.Sprintf(`{"host_id":"host-123","login_user":%q,"public_key":"ssh-rsa AAAA"}`, e.login)); code != http.StatusBadRequest {
		t.Fatal("invalid key accepted")
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	sp2, _ := ssh.NewPublicKey(pub2)
	extra := fmt.Sprintf(`{"host_id":"host-123","login_user":%q,"public_key":%q,"principal":"tenant:t1:host:host-456:login:root"}`, e.login, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp2))))
	if code, _ := call(extra); code != http.StatusBadRequest {
		t.Fatal("extra field accepted")
	}
	// Cookie-authenticated native create needs CSRF; the tunnel needs a bearer.
	var v sessions.View
	if code := alice.post("/api/v1/native-sessions", "", map[string]string{"host_id": "host-123", "login_user": e.login, "public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp2)))}, &v); code != http.StatusCreated {
		t.Fatalf("cookie create %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.web.URL, "http")+v.TunnelPath, &websocket.DialOptions{
		HTTPClient: alice.c, Subprotocols: []string{protocol.SubprotocolNative}, HTTPHeader: http.Header{"Origin": {e.web.URL}},
	})
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie tunnel: %v", err)
	}
	// A native session cannot be attached as a browser terminal.
	if _, err := alice.attach(v, e.web.URL); err == nil {
		t.Fatal("native session attached as web terminal")
	}
	// Bad token.
	req, _ := http.NewRequest(http.MethodGet, e.web.URL+"/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer osm_invalid")
	r2, _ := http.DefaultClient.Do(req)
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token %d", r2.StatusCode)
	}
	// CLI approval requires same-origin POST.
	req, _ = http.NewRequest(http.MethodPost, e.web.URL+"/auth/cli", strings.NewReader("csrf=x"))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r3, _ := alice.c.Do(req)
	if r3.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin approve %d", r3.StatusCode)
	}
}
