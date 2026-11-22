package e2e

// Interop with a real step-ca (M0 / B01–B06, B10). The CA is created from
// scratch in a temp dir with the dedicated JWK provisioner and the templates
// shipped in docs/design/config/step-ca; nothing outside the temp dir is read
// or written. Skipped when `step` / `step-ca` are not on PATH.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
)

const stepProvisioner = "web-ssh"

type stepCA struct {
	url    string
	root   string
	cfg    ca.StepConfig
	userCA string
	signer jose.Signer // provisioner key, for hand-built negative requests
	http   *http.Client
}

// startStepCA initialises and runs an isolated step-ca under dir.
func startStepCA(t *testing.T, dir string) *stepCA {
	t.Helper()
	for _, bin := range []string{"step", "step-ca"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH; real step-ca interop skipped", bin)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	steppath := filepath.Join(dir, "step")
	caPass := filepath.Join(dir, "ca.pass")
	provPass := filepath.Join(dir, "prov.pass")
	// Throwaway test-only passwords for a CA that lives in a temp dir.
	if err := os.WriteFile(caPass, []byte(randomToken()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(provPass, []byte(randomToken()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	step := func(args ...string) {
		cmd := exec.Command("step", args...)
		cmd.Env = append(os.Environ(), "STEPPATH="+steppath, "STEP_CONSOLE=false")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("step %s: %v\n%s", args[0:3], err, out)
		}
	}
	step("ca", "init", "--deployment-type", "standalone", "--name", "osmium-e2e",
		"--dns", "127.0.0.1", "--address", addr, "--provisioner", "admin",
		"--password-file", caPass, "--provisioner-password-file", caPass, "--ssh")
	tpl, err := filepath.Abs("../../docs/design/config/step-ca")
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(steppath, "config", "ca.json")
	step("ca", "provisioner", "add", stepProvisioner, "--type", "JWK", "--create",
		"--password-file", provPass,
		"--ssh-user-min-dur", "1m", "--ssh-user-default-dur", "1m", "--ssh-user-max-dur", "1m",
		"--disable-ssh-ca-host",
		"--ssh-template", filepath.Join(tpl, "web-user.tpl"),
		"--x509-template", filepath.Join(tpl, "deny-x509.tpl"),
		"--ca-config", cfgPath)

	// The provisioner's encrypted private JWK is what the Server is given.
	var conf struct {
		Authority struct {
			Provisioners []struct {
				Name         string `json:"name"`
				EncryptedKey string `json:"encryptedKey"`
			} `json:"provisioners"`
		} `json:"authority"`
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &conf); err != nil {
		t.Fatal(err)
	}
	jwkFile := filepath.Join(dir, "web-ssh.jwk")
	var encKey string
	for _, p := range conf.Authority.Provisioners {
		if p.Name == stepProvisioner {
			encKey = p.EncryptedKey
		}
	}
	if encKey == "" {
		t.Fatal("provisioner web-ssh not found in ca.json")
	}
	if err := os.WriteFile(jwkFile, []byte(encKey), 0o600); err != nil {
		t.Fatal(err)
	}
	userCA, err := os.ReadFile(filepath.Join(steppath, "certs", "ssh_user_ca_key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("step-ca", cfgPath, "--password-file", caPass)
	cmd.Env = append(os.Environ(), "STEPPATH="+steppath)
	logf, _ := os.Create(filepath.Join(dir, "step-ca.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() || os.Getenv("E2E_LOG") != "" {
			b, _ := os.ReadFile(filepath.Join(dir, "step-ca.log"))
			t.Logf("step-ca log:\n%s", b)
		}
	})

	s := &stepCA{url: "https://" + addr, root: filepath.Join(steppath, "certs", "root_ca.crt"), userCA: strings.TrimSpace(string(userCA))}
	pemRoot, err := os.ReadFile(s.root)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemRoot)
	s.http = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := s.http.Get(s.url + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("step-ca did not become healthy: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.cfg = ca.StepConfig{
		URL: s.url, RootCAFile: s.root, ProvisionerName: stepProvisioner,
		JWKFile: jwkFile, JWKPasswordFile: provPass, Timeout: 10 * time.Second,
		UserCAPublicKeys: []string{s.userCA},
	}
	pw, _ := os.ReadFile(provPass)
	jwk, err := ca.ParseJWK([]byte(encKey), bytes.TrimSpace(pw))
	if err != nil {
		t.Fatal(err)
	}
	if s.signer, err = ca.NewJWKSigner(jwk); err != nil {
		t.Fatal(err)
	}
	return s
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// realStepCA is a caSource backed by a real step-ca.
func realStepCA(out **stepCA) caSource {
	return func(e *env) (ca.StepConfig, string) {
		s := startStepCA(e.t, filepath.Join(e.dir, "stepca"))
		*out = s
		return s.cfg, s.userCA
	}
}

func newUserKey(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return sp, priv
}

// sshPost sends a hand-built /1.0/ssh/sign request with arbitrary token claims.
func (s *stepCA) sshPost(t *testing.T, mutate func(*ca.TokenClaims), body func(*ca.SignRequest)) (int, string) {
	t.Helper()
	pub, _ := newUserKey(t)
	now := time.Now()
	var c ca.TokenClaims
	c.Issuer, c.Subject = stepProvisioner, "negative-test"
	c.Audience = jwt.Audience{s.url + "/1.0/ssh/sign"}
	c.IssuedAt, c.NotBefore, c.Expiry = jwt.NewNumericDate(now), jwt.NewNumericDate(now), jwt.NewNumericDate(now.Add(2*time.Minute))
	c.ID = randomToken()
	c.Step.SSH = &ca.SSHOptions{CertType: "user", KeyID: "negative-test", Principals: []string{"tenant:t1:host:host-123:login:ops"}}
	if mutate != nil {
		mutate(&c)
	}
	ott, err := jwt.Signed(s.signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	req := ca.SignRequest{PublicKey: pub.Marshal(), OTT: ott, CertType: c.Step.SSH.CertType, KeyID: c.Step.SSH.KeyID, Principals: c.Step.SSH.Principals}
	if body != nil {
		body(&req)
	}
	return s.post(t, "/1.0/ssh/sign", req)
}

func (s *stepCA) post(t *testing.T, path string, v any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(v)
	resp, err := s.http.Post(s.url+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(data)
}

// B01/B05/B06/B07/B10 against the real CA and the shipped templates.
func TestStepCAInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e skipped in -short mode")
	}
	s := startStepCA(t, t.TempDir())
	signer, err := ca.NewStepCA(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	principal := authz.Principal("t1", "host-123", "ops")

	t.Run("B01_validity_window", func(t *testing.T) {
		pub, _ := newUserKey(t)
		before := time.Now()
		cert, err := signer.SignUserCert(context.Background(), ca.Request{PublicKey: pub, KeyID: "user:alice/session:s1/attempt:a1", Principal: principal})
		if err != nil {
			t.Fatal(err)
		}
		after := time.Now()
		va, vb := time.Unix(int64(cert.ValidAfter), 0), time.Unix(int64(cert.ValidBefore), 0)
		t.Logf("B01 measured: request=%s valid_after=%s (%.0fs before request) valid_before=%s (%.0fs after request), total window %.0fs",
			before.UTC().Format(time.RFC3339), va.UTC().Format(time.RFC3339), before.Sub(va).Seconds(),
			vb.UTC().Format(time.RFC3339), vb.Sub(before).Seconds(), vb.Sub(va).Seconds())
		// Remaining validity after issuance is the configured 60s (+1s rounding).
		if rem := vb.Sub(after); rem > 61*time.Second || rem < 50*time.Second {
			t.Fatalf("remaining validity %s, want ≈60s", rem)
		}
		if va.After(before) {
			t.Fatalf("valid_after %s is after the request time", va)
		}
		if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != principal {
			t.Fatalf("principals %v", cert.ValidPrincipals)
		}
		if len(cert.Extensions) != 1 || cert.Extensions["permit-pty"] != "" || len(cert.CriticalOptions) != 0 {
			t.Fatalf("extensions %v options %v: template must yield only permit-pty", cert.Extensions, cert.CriticalOptions)
		}
	})

	t.Run("B05_verifier_rejects_other_ca", func(t *testing.T) {
		// A Verifier that trusts a different CA must refuse step-ca's cert.
		other, _ := newUserKey(t)
		v, err := ca.NewVerifier([]string{string(ssh.MarshalAuthorizedKey(other))}, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := newUserKey(t)
		r := ca.Request{PublicKey: pub, KeyID: "k", Principal: principal}
		cert, err := signer.SignUserCert(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(cert, r, time.Now()); err == nil {
			t.Fatal("certificate from an untrusted CA accepted")
		}
	})

	t.Run("B06_host_certificate_refused", func(t *testing.T) {
		code, body := s.sshPost(t, func(c *ca.TokenClaims) { c.Step.SSH.CertType = "host" }, nil)
		if code < 400 {
			t.Fatalf("host certificate issued: %d %s", code, body)
		}
	})

	t.Run("B06_multiple_principals_refused", func(t *testing.T) {
		code, body := s.sshPost(t, func(c *ca.TokenClaims) {
			c.Step.SSH.Principals = []string{principal, authz.Principal("t1", "host-456", "ops")}
		}, nil)
		if code < 400 {
			t.Fatalf("two principals issued: %d %s", code, body)
		}
	})

	t.Run("B06_x509_refused", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil.example"}, DNSNames: []string{"evil.example"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		var c ca.TokenClaims
		c.Issuer, c.Subject = stepProvisioner, "evil.example"
		c.Audience = jwt.Audience{s.url + "/1.0/sign"}
		c.IssuedAt, c.NotBefore, c.Expiry = jwt.NewNumericDate(now), jwt.NewNumericDate(now), jwt.NewNumericDate(now.Add(2*time.Minute))
		c.ID = randomToken()
		c.SANs = []string{"evil.example"}
		ott, err := jwt.Signed(s.signer).Claims(c).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
		code, body := s.post(t, "/1.0/sign", map[string]string{"csr": csr, "ott": ott})
		if code < 400 {
			t.Fatalf("X.509 certificate issued: %d %s", code, body)
		}
	})

	t.Run("B07_longer_validity_not_granted", func(t *testing.T) {
		code, body := s.sshPost(t, func(c *ca.TokenClaims) { c.Step.SSH.ValidBefore = "10m" }, func(r *ca.SignRequest) { r.ValidBefore = "10m" })
		if code < 400 {
			var sr ca.SignResponse
			_ = json.Unmarshal([]byte(body), &sr)
			cert, err := ca.DecodeCert(sr.Certificate)
			if err != nil {
				t.Fatalf("unexpected body: %s", body)
			}
			if d := time.Until(time.Unix(int64(cert.ValidBefore), 0)); d > 61*time.Second {
				t.Fatalf("CA granted %s, above the 1m provisioner maximum", d)
			}
		}
	})

	t.Run("B10_token_replay_refused", func(t *testing.T) {
		pub, _ := newUserKey(t)
		now := time.Now()
		r := ca.Request{PublicKey: pub, KeyID: "replay", Principal: principal}
		ott, err := ca.Token(s.signer, stepProvisioner, s.url+"/1.0/ssh/sign", r, "", now)
		if err != nil {
			t.Fatal(err)
		}
		req := ca.SignRequest{PublicKey: pub.Marshal(), OTT: ott, CertType: "user", KeyID: r.KeyID, Principals: []string{principal}}
		if code, body := s.post(t, "/1.0/ssh/sign", req); code >= 400 {
			t.Fatalf("first use rejected: %d %s", code, body)
		}
		if code, _ := s.post(t, "/1.0/ssh/sign", req); code < 400 {
			t.Fatal("one-time token accepted twice")
		}
	})
}

// B02/B03/B04/B12 with a real step-ca certificate against a real sshd:
// an established connection survives certificate expiry (and can open new
// channels), the same certificate can authenticate twice while valid (so the
// application, not the certificate, must enforce one key per attempt), and
// after expiry it can no longer authenticate.
func TestStepCACertExpiry(t *testing.T) {
	var s *stepCA
	e := newEnvWithCA(t, realStepCA(&s))
	pub, priv := newUserKey(t)
	cert, err := e.signer.SignUserCert(context.Background(), ca.Request{PublicKey: pub, KeyID: "expiry-test", Principal: authz.Principal("t1", "host-123", e.login)})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := ssh.NewSignerFromKey(priv)
	certSigner, err := ssh.NewCertSigner(cert, base)
	if err != nil {
		t.Fatal(err)
	}
	target := e.sshd["host-123"]
	dial := func() (*ssh.Client, error) {
		return ssh.Dial("tcp", target.addr, &ssh.ClientConfig{
			User: e.login, Auth: []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback: ssh.FixedHostKey(target.hostKey), Timeout: 5 * time.Second,
		})
	}
	run := func(c *ssh.Client, cmd string) string {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatalf("new channel: %v", err)
		}
		defer sess.Close()
		out, err := sess.Output(cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		return strings.TrimSpace(string(out))
	}

	first, err := dial()
	if err != nil {
		t.Fatalf("A01 with real CA cert: %v", err)
	}
	defer first.Close()
	if got := run(first, "echo before"); got != "before" {
		t.Fatalf("got %q", got)
	}
	// B04: certificates are not one-time.
	second, err := dial()
	if err != nil {
		t.Fatalf("B04: second auth with the same valid cert failed: %v", err)
	}
	second.Close()

	wait := time.Until(time.Unix(int64(cert.ValidBefore), 0)) + 2*time.Second
	t.Logf("waiting %s for the certificate to expire", wait.Round(time.Second))
	time.Sleep(wait)

	// B02 + B12: established transport keeps working, new channels included.
	if got := run(first, "echo after"); got != "after" {
		t.Fatalf("B02: got %q", got)
	}
	// B03: expired certificate cannot authenticate a new connection.
	if c, err := dial(); err == nil {
		c.Close()
		t.Fatal("B03: expired certificate accepted for a new connection")
	}
}

// The full Web and native flows with certificates from a real step-ca.
func TestStepCAEndToEnd(t *testing.T) {
	var s *stepCA
	e := newEnvWithCA(t, realStepCA(&s))
	e.startAgent("host-123")
	alice := e.signIn("alice")

	v, code := alice.create("host-123")
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	tm, err := alice.attach(v, e.web.URL)
	if err != nil {
		t.Fatal(err)
	}
	tm.waitActive()
	tm.roundTrip("realca")
	tm.send("exit\r")
	if x := tm.waitExit(); x.Reason != "shell_exit" {
		t.Fatalf("exit %+v", x)
	}

	// A05 with a real certificate: the host-123 principal does not open host-456.
	pub, priv := newUserKey(t)
	cert, err := e.signer.SignUserCert(context.Background(), ca.Request{PublicKey: pub, KeyID: "cross-host", Principal: authz.Principal("t1", "host-123", e.login)})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := ssh.NewSignerFromKey(priv)
	cs, _ := ssh.NewCertSigner(cert, base)
	other := e.sshd["host-456"]
	if c, err := ssh.Dial("tcp", other.addr, &ssh.ClientConfig{User: e.login, Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)}, HostKeyCallback: ssh.FixedHostKey(other.hostKey), Timeout: 5 * time.Second}); err == nil {
		c.Close()
		t.Fatal("A05: host-123 certificate accepted by host-456")
	}

	// Native OpenSSH client + ssh-agent through the same real CA.
	c := e.newCLI(t)
	c.login(alice)
	out, errOut, rc := c.run(30*time.Second, "ssh", "host-123", "echo", "native-realca")
	if rc != 0 || !strings.Contains(out, "native-realca") {
		t.Fatalf("native: %d %q %q", rc, out, errOut)
	}
}
