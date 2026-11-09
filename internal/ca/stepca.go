// Package ca obtains short-lived SSH user certificates from step-ca through a
// dedicated JWK provisioner and validates every returned field before use.
package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"
)

// Request describes one certificate for one connection attempt. Every field
// is derived by the server, never taken from the browser.
type Request struct {
	PublicKey ssh.PublicKey
	KeyID     string
	Principal string
}

// Signer issues SSH user certificates.
type Signer interface {
	SignUserCert(ctx context.Context, r Request) (*ssh.Certificate, error)
}

// StepConfig configures the step-ca client.
type StepConfig struct {
	URL              string // e.g. https://ca.internal:9000
	RootCAFile       string // PEM bundle trusted for the CA's TLS identity
	ProvisionerName  string // JWK provisioner name (token iss)
	JWKFile          string // provisioner private JWK (plain or JWE-encrypted)
	JWKPasswordFile  string // password for an encrypted JWK
	Audience         string // default URL + "/1.0/ssh/sign"
	SignPath         string // default "/1.0/ssh/sign"
	ValidBefore      string // optional; passed to step-ca as validBefore (e.g. "60s")
	Timeout          time.Duration
	UserCAPublicKeys []string // authorized_keys lines of the trusted SSH User CA
	MaxLifetime      time.Duration
	AllowedExts      []string
}

// StepCA is a Signer backed by step-ca.
type StepCA struct {
	cfg      StepConfig
	signer   jose.Signer
	client   *http.Client
	verifier *Verifier
}

// NewStepCA loads keys and builds the client.
func NewStepCA(cfg StepConfig) (*StepCA, error) {
	if cfg.URL == "" || cfg.ProvisionerName == "" || cfg.JWKFile == "" {
		return nil, errors.New("ca: url, provisioner_name and jwk_file are required")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if !strings.HasPrefix(cfg.URL, "https://") {
		return nil, errors.New("ca: url must be https")
	}
	if cfg.Audience == "" {
		cfg.Audience = cfg.URL + "/1.0/ssh/sign"
	}
	if cfg.SignPath == "" {
		cfg.SignPath = "/1.0/ssh/sign"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	raw, err := os.ReadFile(cfg.JWKFile)
	if err != nil {
		return nil, fmt.Errorf("ca: read jwk: %w", err)
	}
	var password []byte
	if cfg.JWKPasswordFile != "" {
		if password, err = os.ReadFile(cfg.JWKPasswordFile); err != nil {
			return nil, fmt.Errorf("ca: read jwk password: %w", err)
		}
		password = bytes.TrimRight(password, "\r\n")
	}
	jwk, err := ParseJWK(raw, password)
	if err != nil {
		return nil, err
	}
	signer, err := NewJWKSigner(jwk)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.RootCAFile != "" {
		pem, err := os.ReadFile(cfg.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("ca: read root: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca: no certificates in root_ca_file")
		}
		tlsCfg.RootCAs = pool
	}
	v, err := NewVerifier(cfg.UserCAPublicKeys, cfg.MaxLifetime, cfg.AllowedExts)
	if err != nil {
		return nil, err
	}
	return &StepCA{
		cfg:    cfg,
		signer: signer,
		client: &http.Client{
			Transport:     &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		verifier: v,
	}, nil
}

// ParseJWK parses a plain JWK or a JWE-encrypted JWK (step crypto jwk create).
func ParseJWK(raw, password []byte) (*jose.JSONWebKey, error) {
	raw = bytes.TrimSpace(raw)
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err == nil && jwk.Key != nil {
		if jwk.IsPublic() {
			return nil, errors.New("ca: jwk_file holds a public key, need the provisioner private key")
		}
		return &jwk, nil
	}
	if len(password) == 0 {
		return nil, errors.New("ca: jwk_file is not a plain JWK and no password was configured")
	}
	enc, err := jose.ParseEncrypted(string(raw),
		[]jose.KeyAlgorithm{jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW},
		[]jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("ca: parse encrypted jwk: %w", err)
	}
	plain, err := enc.Decrypt(password)
	if err != nil {
		return nil, errors.New("ca: decrypt jwk failed")
	}
	if err := json.Unmarshal(plain, &jwk); err != nil || jwk.Key == nil || jwk.IsPublic() {
		return nil, errors.New("ca: decrypted jwk is not a private key")
	}
	return &jwk, nil
}

// NewJWKSigner builds a JWS signer that sets kid from the JWK.
func NewJWKSigner(jwk *jose.JSONWebKey) (jose.Signer, error) {
	alg := jose.SignatureAlgorithm(jwk.Algorithm)
	if alg == "" {
		alg = jose.ES256
	}
	if jwk.KeyID == "" {
		return nil, errors.New("ca: jwk has no kid")
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID)
	return jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jwk.Key}, opts)
}

// SSHOptions is the step.ssh claim of a provisioning token.
type SSHOptions struct {
	CertType    string   `json:"certType"`
	KeyID       string   `json:"keyID"`
	Principals  []string `json:"principals"`
	ValidBefore string   `json:"validBefore,omitempty"`
}

// TokenClaims is the JWK provisioning token payload for SSH signing.
type TokenClaims struct {
	jwt.Claims
	SANs []string `json:"sans,omitempty"`
	Step struct {
		SSH *SSHOptions `json:"ssh"`
	} `json:"step"`
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Token builds a one-time JWK provisioning token bound to r.
func Token(signer jose.Signer, issuer, audience string, r Request, validBefore string, now time.Time) (string, error) {
	var c TokenClaims
	c.Issuer = issuer
	c.Subject = r.KeyID
	c.Audience = jwt.Audience{audience}
	c.IssuedAt = jwt.NewNumericDate(now)
	c.NotBefore = jwt.NewNumericDate(now)
	c.Expiry = jwt.NewNumericDate(now.Add(2 * time.Minute))
	c.ID = randomHex(16)
	c.SANs = []string{r.Principal}
	c.Step.SSH = &SSHOptions{CertType: "user", KeyID: r.KeyID, Principals: []string{r.Principal}, ValidBefore: validBefore}
	return jwt.Signed(signer).Claims(c).Serialize()
}

// SignRequest is the body of POST /ssh/sign.
type SignRequest struct {
	PublicKey   []byte   `json:"publicKey"`
	OTT         string   `json:"ott"`
	CertType    string   `json:"certType"`
	KeyID       string   `json:"keyID"`
	Principals  []string `json:"principals"`
	ValidBefore string   `json:"validBefore,omitempty"`
}

// SignResponse is the relevant part of the step-ca response.
type SignResponse struct {
	Certificate string `json:"crt"`
}

// SignUserCert implements Signer. A timeout never triggers a retry here: the
// caller abandons the attempt and a new attempt uses a new key and token.
func (s *StepCA) SignUserCert(ctx context.Context, r Request) (*ssh.Certificate, error) {
	ott, err := Token(s.signer, s.cfg.ProvisionerName, s.cfg.Audience, r, s.cfg.ValidBefore, time.Now())
	if err != nil {
		return nil, fmt.Errorf("ca: build token: %w", err)
	}
	body, _ := json.Marshal(SignRequest{
		PublicKey:   r.PublicKey.Marshal(),
		OTT:         ott,
		CertType:    "user",
		KeyID:       r.KeyID,
		Principals:  []string{r.Principal},
		ValidBefore: s.cfg.ValidBefore,
	})
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL+s.cfg.SignPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ca: request failed: %w", redact(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("ca: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("ca: sign rejected with HTTP %d", resp.StatusCode)
	}
	var sr SignResponse
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, errors.New("ca: malformed sign response")
	}
	cert, err := DecodeCert(sr.Certificate)
	if err != nil {
		return nil, err
	}
	if err := s.verifier.Verify(cert, r, time.Now()); err != nil {
		return nil, err
	}
	return cert, nil
}

// redact strips the request URL details that net/http wraps into errors.
func redact(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

// DecodeCert decodes base64 OpenSSH certificate wire bytes.
func DecodeCert(b64 string) (*ssh.Certificate, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("ca: certificate is not base64")
	}
	pk, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, errors.New("ca: certificate wire bytes invalid")
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("ca: response is not an SSH certificate")
	}
	return cert, nil
}

// Verifier checks a returned certificate against what was requested.
type Verifier struct {
	cas         []ssh.PublicKey
	maxLifetime time.Duration
	allowedExts []string
}

// NewVerifier builds a Verifier. maxLifetime bounds ValidBefore-now (default
// 5m) and allowedExts defaults to ["permit-pty"].
func NewVerifier(caKeys []string, maxLifetime time.Duration, allowedExts []string) (*Verifier, error) {
	if len(caKeys) == 0 {
		return nil, errors.New("ca: user_ca_public_keys required to verify issued certificates")
	}
	v := &Verifier{maxLifetime: maxLifetime, allowedExts: allowedExts}
	if v.maxLifetime <= 0 {
		v.maxLifetime = 5 * time.Minute
	}
	if v.allowedExts == nil {
		v.allowedExts = []string{"permit-pty"}
	}
	for _, line := range caKeys {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("ca: bad user CA key: %w", err)
		}
		v.cas = append(v.cas, k)
	}
	return v, nil
}

// Verify enforces type, key, CA, principal set, Key ID, validity and options.
func (v *Verifier) Verify(cert *ssh.Certificate, r Request, now time.Time) error {
	fail := func(what string) error { return fmt.Errorf("ca: issued certificate rejected: %s", what) }
	if cert.CertType != ssh.UserCert {
		return fail("not a user certificate")
	}
	if !bytes.Equal(cert.Key.Marshal(), r.PublicKey.Marshal()) {
		return fail("public key mismatch")
	}
	if !slices.ContainsFunc(v.cas, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), cert.SignatureKey.Marshal()) }) {
		return fail("signed by an untrusted CA")
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != r.Principal {
		return fail("principal set mismatch")
	}
	if cert.KeyId != r.KeyID {
		return fail("key id mismatch")
	}
	if len(cert.CriticalOptions) != 0 {
		return fail("unexpected critical options")
	}
	for ext := range cert.Extensions {
		if !slices.Contains(v.allowedExts, ext) {
			return fail("unexpected extension " + ext)
		}
	}
	unix := uint64(now.Unix())
	if cert.ValidBefore == ssh.CertTimeInfinity || cert.ValidBefore <= unix {
		return fail("already expired or infinite")
	}
	if cert.ValidBefore-unix > uint64(v.maxLifetime/time.Second) {
		return fail("lifetime exceeds limit")
	}
	if cert.ValidAfter > unix+5 {
		return fail("not yet valid")
	}
	checker := &ssh.CertChecker{Clock: func() time.Time { return now }}
	if err := checker.CheckCert(r.Principal, cert); err != nil {
		return fail(err.Error())
	}
	return nil
}
