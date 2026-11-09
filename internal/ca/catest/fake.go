// Package catest is an in-process stand-in for step-ca's JWK provisioner SSH
// signing path, for tests and local development only. It verifies the
// provisioning token like step-ca does (signature, kid, iss, aud, time, jti
// reuse, step.ssh binding) and signs with a 1 minute backdate.
package catest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/ca"
)

// FakeCA is a minimal step-ca SSH signer.
type FakeCA struct {
	Server      *httptest.Server
	Provisioner string
	JWK         *jose.JSONWebKey // private; give to the client
	UserCA      ssh.Signer
	Validity    time.Duration
	Backdate    time.Duration

	mu     sync.Mutex
	used   map[string]bool
	Mutate func(*ssh.Certificate) // fault injection before signing
	Delay  time.Duration
	Down   bool
	Issued []*ssh.Certificate
}

// New starts a TLS fake CA.
func New(provisioner string) (*FakeCA, error) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk := &jose.JSONWebKey{Key: ek, Algorithm: string(jose.ES256), Use: "sig"}
	tp, err := jwk.Thumbprint(cryptoSHA256)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		return nil, err
	}
	f := &FakeCA{Provisioner: provisioner, JWK: jwk, UserCA: caSigner, Validity: 60 * time.Second, Backdate: time.Minute, used: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /1.0/ssh/sign", f.sign)
	mux.HandleFunc("POST /ssh/sign", f.sign)
	f.Server = httptest.NewTLSServer(mux)
	return f, nil
}

// Close stops the server.
func (f *FakeCA) Close() { f.Server.Close() }

// UserCAAuthorizedKey returns the User CA public key line for sshd/verifier.
func (f *FakeCA) UserCAAuthorizedKey() string {
	return string(ssh.MarshalAuthorizedKey(f.UserCA.PublicKey()))
}

// Audience returns the expected token audience.
func (f *FakeCA) Audience() string { return f.Server.URL + "/1.0/ssh/sign" }

func (f *FakeCA) sign(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	down, delay := f.Down, f.Delay
	f.mu.Unlock()
	if down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	var req ca.SignRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	opts, err := f.verifyToken(req.OTT)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if opts.CertType != "user" || req.CertType != "user" {
		http.Error(w, "this provisioner is for SSH user certificates only", http.StatusForbidden)
		return
	}
	if len(opts.Principals) != 1 || !slices.Equal(req.Principals, opts.Principals) || req.KeyID != opts.KeyID {
		http.Error(w, "request does not match token", http.StatusForbidden)
		return
	}
	pub, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, "bad public key", http.StatusBadRequest)
		return
	}
	now := time.Now()
	var serial [8]byte
	_, _ = rand.Read(serial[:])
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           opts.KeyID,
		ValidPrincipals: opts.Principals,
		ValidAfter:      uint64(now.Add(-f.Backdate).Unix()),
		ValidBefore:     uint64(now.Add(f.Validity).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	f.mu.Lock()
	mutate := f.Mutate
	f.mu.Unlock()
	if mutate != nil {
		mutate(cert)
	}
	if err := cert.SignCert(rand.Reader, f.UserCA); err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.Issued = append(f.Issued, cert)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"crt": base64.StdEncoding.EncodeToString(cert.Marshal())})
}

func (f *FakeCA) verifyToken(tok string) (*ca.SSHOptions, error) {
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA, jose.RS256})
	if err != nil {
		return nil, errors.New("invalid token")
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID != f.JWK.KeyID {
		return nil, errors.New("wrong kid")
	}
	var c ca.TokenClaims
	if err := parsed.Claims(f.JWK.Public().Key, &c); err != nil {
		return nil, errors.New("bad signature")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: f.Provisioner, AnyAudience: jwt.Audience{f.Audience(), f.Server.URL + "/ssh/sign"}, Time: time.Now()}, time.Minute); err != nil {
		return nil, err
	}
	if c.Subject == "" || c.ID == "" || c.Step.SSH == nil {
		return nil, errors.New("not an SSH token")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used[c.ID] {
		return nil, errors.New("token already used")
	}
	f.used[c.ID] = true
	return c.Step.SSH, nil
}

// SetDown toggles CA availability.
func (f *FakeCA) SetDown(down bool) { f.mu.Lock(); f.Down = down; f.mu.Unlock() }

// SetDelay sets an artificial signing delay.
func (f *FakeCA) SetDelay(d time.Duration) { f.mu.Lock(); f.Delay = d; f.mu.Unlock() }

// SetMutate installs a fault injection hook.
func (f *FakeCA) SetMutate(m func(*ssh.Certificate)) { f.mu.Lock(); f.Mutate = m; f.mu.Unlock() }

// ClientConfig writes the JWK and TLS root into dir and returns a matching
// client configuration.
func (f *FakeCA) ClientConfig(dir string) (ca.StepConfig, error) {
	jwkJSON, err := json.Marshal(f.JWK)
	if err != nil {
		return ca.StepConfig{}, err
	}
	jwkPath := filepath.Join(dir, "provisioner.jwk")
	if err := os.WriteFile(jwkPath, jwkJSON, 0o600); err != nil {
		return ca.StepConfig{}, err
	}
	rootPath := filepath.Join(dir, "ca-root.pem")
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})
	if err := os.WriteFile(rootPath, root, 0o644); err != nil {
		return ca.StepConfig{}, err
	}
	return ca.StepConfig{
		URL:              f.Server.URL,
		RootCAFile:       rootPath,
		ProvisionerName:  f.Provisioner,
		JWKFile:          jwkPath,
		UserCAPublicKeys: []string{f.UserCAAuthorizedKey()},
		Timeout:          5 * time.Second,
	}, nil
}
