package agent

import (
	"crypto/x509"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/indexyz/osmium/internal/devpki"
)

func TestCertReloaderHotReloadAndFallback(t *testing.T) {
	dir := t.TempDir()
	ca, err := devpki.NewCA("agent-ca")
	if err != nil {
		t.Fatal(err)
	}
	cert1, err := ca.Issue("agent-v1", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := devpki.WriteFiles(dir, "client", cert1.Cert, cert1.Key); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	r, err := newCertReloader(certPath, keyPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	got1, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	x1, _ := x509.ParseCertificate(got1.Certificate[0])
	if x1.Subject.CommonName != "agent-v1" {
		t.Fatalf("initial CN=%q", x1.Subject.CommonName)
	}

	// Rotate certificate files on disk with a newer mtime.
	cert2, err := ca.Issue("agent-v2", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := devpki.WriteFiles(dir, "client", cert2.Cert, cert2.Key); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)

	got2, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	x2, _ := x509.ParseCertificate(got2.Certificate[0])
	if x2.Subject.CommonName != "agent-v2" {
		t.Fatalf("rotated CN=%q, want agent-v2", x2.Subject.CommonName)
	}

	// Corrupt the certificate on disk: reloader must keep last good cert.
	_ = os.WriteFile(certPath, []byte("corrupt-pem"), 0o600)
	future2 := future.Add(2 * time.Second)
	_ = os.Chtimes(certPath, future2, future2)
	got3, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	x3, _ := x509.ParseCertificate(got3.Certificate[0])
	if x3.Subject.CommonName != "agent-v2" {
		t.Fatalf("fallback CN=%q, want agent-v2", x3.Subject.CommonName)
	}
}
