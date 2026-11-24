package sshgateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func genSignerAndPub(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func signHostCert(t *testing.T, caSigner ssh.Signer, hostPub ssh.PublicKey, certType uint32, principals []string, validAfter, validBefore time.Time) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        certType,
		KeyId:           "host-cert-test",
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestHostIdentityCallbackSupportsPinsAndHostCAFailClosed(t *testing.T) {
	caSigner, caPub := genSignerAndPub(t)
	rogueCASigner, _ := genSignerAndPub(t)
	_, hostPub := genSignerAndPub(t)
	_, otherPub := genSignerAndPub(t)

	now := time.Now()
	validCert := signHostCert(t, caSigner, hostPub, ssh.HostCert, []string{"host-123"}, now.Add(-time.Minute), now.Add(time.Hour))
	wrongHostCert := signHostCert(t, caSigner, hostPub, ssh.HostCert, []string{"host-456"}, now.Add(-time.Minute), now.Add(time.Hour))
	expiredCert := signHostCert(t, caSigner, hostPub, ssh.HostCert, []string{"host-123"}, now.Add(-2*time.Hour), now.Add(-time.Hour))
	rogueCert := signHostCert(t, rogueCASigner, hostPub, ssh.HostCert, []string{"host-123"}, now.Add(-time.Minute), now.Add(time.Hour))
	userCertMasquerade := signHostCert(t, caSigner, hostPub, ssh.UserCert, []string{"host-123"}, now.Add(-time.Minute), now.Add(time.Hour))

	// 1) Host CA only (no pinned keys): accepts valid host cert for host-123, rejects all negative cases.
	cb := HostIdentityCallback(nil, []ssh.PublicKey{caPub}, []string{"host-123"})
	if err := cb("host-123", nil, validCert); err != nil {
		t.Fatalf("valid host cert rejected: %v", err)
	}
	for name, key := range map[string]ssh.PublicKey{
		"plain-key-without-pin": hostPub,
		"wrong-host-principal":  wrongHostCert,
		"expired-host-cert":     expiredCert,
		"untrusted-ca":          rogueCert,
		"user-cert-as-host":     userCertMasquerade,
	} {
		if err := cb("host-123", nil, key); !errors.Is(err, ErrHostKeyMismatch) {
			t.Errorf("%s: got %v, want ErrHostKeyMismatch", name, err)
		}
	}

	// 2) Pin only (no Host CA): accepts pinned plain key, rejects certs even if signed.
	pinOnly := HostIdentityCallback([]ssh.PublicKey{hostPub}, nil, []string{"host-123"})
	if err := pinOnly("host-123", nil, hostPub); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	if err := pinOnly("host-123", nil, otherPub); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("unpinned key accepted: %v", err)
	}
	if err := pinOnly("host-123", nil, validCert); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("cert accepted when no Host CA configured: %v", err)
	}
}
