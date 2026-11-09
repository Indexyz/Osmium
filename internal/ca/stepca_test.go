package ca_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/ca/catest"
)

func setup(t *testing.T) (*catest.FakeCA, *ca.StepCA) {
	t.Helper()
	f, err := catest.New("web-ssh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	cfg, err := f.ClientConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.NewStepCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func newReq(t *testing.T) ca.Request {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return ca.Request{PublicKey: sp, KeyID: "user:u-alice/session:s001", Principal: "tenant:t1:host:host-123:login:ops"}
}

// B01: record the actual validity window semantics (backdate included).
func TestSignAndVerify(t *testing.T) {
	_, c := setup(t)
	r := newReq(t)
	cert, err := c.SignUserCert(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	if cert.ValidBefore-now > 61 || cert.ValidBefore-cert.ValidAfter < 110 {
		t.Fatalf("unexpected window after=%d before=%d now=%d", cert.ValidAfter, cert.ValidBefore, now)
	}
	if cert.KeyId != r.KeyID || cert.ValidPrincipals[0] != r.Principal {
		t.Fatal("fields")
	}
}

// B05: any mismatching field is refused.
func TestRejectMismatchingCert(t *testing.T) {
	f, c := setup(t)
	mutations := map[string]func(*ssh.Certificate){
		"principal": func(x *ssh.Certificate) { x.ValidPrincipals = []string{"tenant:t1:host:host-456:login:ops"} },
		"extra":     func(x *ssh.Certificate) { x.ValidPrincipals = append(x.ValidPrincipals, "root") },
		"keyid":     func(x *ssh.Certificate) { x.KeyId = "user:u-bob/session:s1" },
		"type":      func(x *ssh.Certificate) { x.CertType = ssh.HostCert },
		"ext":       func(x *ssh.Certificate) { x.Extensions["permit-port-forwarding"] = "" },
		"critical":  func(x *ssh.Certificate) { x.CriticalOptions = map[string]string{"force-command": "id"} },
		"lifetime":  func(x *ssh.Certificate) { x.ValidBefore = uint64(time.Now().Add(time.Hour).Unix()) },
		"infinite":  func(x *ssh.Certificate) { x.ValidBefore = ssh.CertTimeInfinity },
		"expired":   func(x *ssh.Certificate) { x.ValidBefore = uint64(time.Now().Add(-time.Second).Unix()) },
		"publickey": func(x *ssh.Certificate) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			x.Key, _ = ssh.NewPublicKey(pub)
		},
	}
	for name, m := range mutations {
		f.SetMutate(m)
		if _, err := c.SignUserCert(context.Background(), newReq(t)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestUntrustedCA(t *testing.T) {
	f, _ := setup(t)
	cfg, _ := f.ClientConfig(t.TempDir())
	other, _ := catest.New("other")
	defer other.Close()
	cfg.UserCAPublicKeys = []string{other.UserCAAuthorizedKey()}
	c, err := ca.NewStepCA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignUserCert(context.Background(), newReq(t)); err == nil || !strings.Contains(err.Error(), "untrusted CA") {
		t.Fatalf("want untrusted CA, got %v", err)
	}
}

// B10/B11: CA down or slow fails closed without retry.
func TestCAUnavailable(t *testing.T) {
	f, c := setup(t)
	f.SetDown(true)
	if _, err := c.SignUserCert(context.Background(), newReq(t)); err == nil {
		t.Fatal("expected failure")
	}
	f.SetDown(false)
	f.SetDelay(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.SignUserCert(ctx, newReq(t)); err == nil {
		t.Fatal("expected timeout")
	}
}
