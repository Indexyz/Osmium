package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errAgentReadOnly = errors.New("osmium ssh-agent is read-only; certificates are managed automatically")

// DefaultAgentSocketPath returns the default local Unix domain socket path for
// osmium ssh-agent, staying within the ~104-byte sockaddr_un path limit.
func DefaultAgentSocketPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "ssh-agent.sock")
	if len(p) <= 95 {
		return p, nil
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("osmium-%d", os.Getuid()), "a.sock"), nil
}

// SSHAgentOptions configures the built-in local osmium ssh-agent daemon.
type SSHAgentOptions struct {
	SocketPath    string        // default DefaultAgentSocketPath()
	Principals    []string      // optional narrowing subset of authorized cert_role principals
	TTL           time.Duration // optional requested certificate TTL (server-capped)
	RenewBefore   time.Duration // renew before ValidBefore (default min(ttl/4, 15m))
	CheckInterval time.Duration // revocation/disable check interval via GET /api/v1/me (default 60s)
	Log           *slog.Logger
	// OnReady is invoked once the initial certificate is loaded and the agent
	// listener is accepting connections.
	OnReady func(socketPath string, cert *ssh.Certificate)
	// OnRenew is invoked after each successful key-rotating renewal.
	OnRenew func(cert *ssh.Certificate)
	// OnWipe is invoked when in-memory keys are wiped due to revocation,
	// user disablement, or certificate expiration.
	OnWipe func(reason string)
}

// managedAgent wraps an in-memory ssh/agent keyring as a strictly read-only
// agent.ExtendedAgent so local processes can list/sign with the managed
// certificate but can never add, remove, or lock keys.
type managedAgent struct {
	mu   sync.RWMutex
	ring agent.ExtendedAgent
	priv ed25519.PrivateKey
	cert *ssh.Certificate
}

func newManagedAgent() *managedAgent {
	return &managedAgent{ring: agent.NewKeyring().(agent.ExtendedAgent)}
}

func (m *managedAgent) replace(priv ed25519.PrivateKey, cert *ssh.Certificate, comment string) error {
	next := agent.NewKeyring().(agent.ExtendedAgent)
	// Store ONLY the signed certificate identity so OpenSSH never offers an
	// unsigned plain key and only authenticates with the Zero Trust cert.
	if err := next.Add(agent.AddedKey{
		PrivateKey:  priv,
		Certificate: cert,
		Comment:     comment,
	}); err != nil {
		return err
	}
	m.mu.Lock()
	oldPriv := m.priv
	m.ring = next
	m.priv = priv
	m.cert = cert
	m.mu.Unlock()
	clear(oldPriv)
	return nil
}

func (m *managedAgent) wipe() {
	m.mu.Lock()
	oldPriv := m.priv
	m.ring = agent.NewKeyring().(agent.ExtendedAgent)
	m.priv = nil
	m.cert = nil
	m.mu.Unlock()
	clear(oldPriv)
}

func (m *managedAgent) currentCert() *ssh.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

func (m *managedAgent) List() ([]*agent.Key, error) {
	m.mu.RLock()
	r := m.ring
	m.mu.RUnlock()
	return r.List()
}

func (m *managedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	m.mu.RLock()
	r := m.ring
	m.mu.RUnlock()
	return r.Sign(key, data)
}

func (m *managedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	m.mu.RLock()
	r := m.ring
	m.mu.RUnlock()
	return r.SignWithFlags(key, data, flags)
}

func (m *managedAgent) Signers() ([]ssh.Signer, error) {
	m.mu.RLock()
	r := m.ring
	m.mu.RUnlock()
	return r.Signers()
}

func (m *managedAgent) Add(agent.AddedKey) error              { return errAgentReadOnly }
func (m *managedAgent) Remove(ssh.PublicKey) error            { return errAgentReadOnly }
func (m *managedAgent) RemoveAll() error                      { return errAgentReadOnly }
func (m *managedAgent) Lock([]byte) error                     { return errAgentReadOnly }
func (m *managedAgent) Unlock([]byte) error                   { return errAgentReadOnly }
func (m *managedAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (a *API) issueRoleInMemory(ctx context.Context, principals []string, ttl time.Duration) (ed25519.PrivateKey, *ssh.Certificate, *DirectCertResponse, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	req := DirectCertRequest{
		Mode:       "role",
		Principals: principals,
		PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	}
	if ttl > 0 {
		req.TTL = ttl.String()
	}
	resp, err := a.IssueDirectCert(ctx, req)
	if err != nil {
		clear(priv)
		return nil, nil, nil, err
	}
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	cert, ok := certKey.(*ssh.Certificate)
	if err != nil || !ok || !bytes.Equal(cert.Key.Marshal(), sshPub.Marshal()) {
		clear(priv)
		return nil, nil, nil, errors.New("server returned a certificate for a different key")
	}
	return priv, cert, resp, nil
}

func isAuthRevokedError(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden
	}
	return false
}

func computeRenewDelay(cert *ssh.Certificate, configuredBefore time.Duration) time.Duration {
	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	remaining := time.Until(validBefore)
	if remaining <= 0 {
		return time.Second
	}
	before := configuredBefore
	if before <= 0 {
		before = min(remaining/4, 15*time.Minute)
		if before < time.Second {
			before = remaining / 2
		}
	}
	if before >= remaining {
		before = remaining / 2
	}
	delay := remaining - before
	if delay < 200*time.Millisecond {
		delay = 200 * time.Millisecond
	}
	return delay
}

func prepareUnixSocket(path string) (net.Listener, error) {
	if len(path) >= 104 {
		return nil, fmt.Errorf("socket path %q is too long (%d bytes; Unix domain sockets are limited to ~104 bytes); pass a shorter --socket path", path, len(path))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(filepath.Dir(path), 0o700)
	if fi, err := os.Lstat(path); err == nil {
		// Never blindly remove a regular file or directory.
		if fi.Mode()&os.ModeSocket == 0 && runtime.GOOS != "windows" {
			return nil, fmt.Errorf("refusing to overwrite non-socket file %s", path)
		}
		if fi.IsDir() {
			return nil, fmt.Errorf("socket path %s is a directory", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen ssh-agent socket %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = ln.Close()
			_ = os.Remove(path)
			return nil, err
		}
	}
	return ln, nil
}

// RunSSHAgent runs a local read-only OpenSSH agent holding an in-memory
// ephemeral Ed25519 key and signed role certificate. It rotates keys before
// expiry and immediately wipes memory if credentials are revoked or disabled.
func (a *API) RunSSHAgent(ctx context.Context, o SSHAgentOptions) error {
	log := o.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	sockPath := o.SocketPath
	if sockPath == "" {
		var err error
		sockPath, err = DefaultAgentSocketPath()
		if err != nil {
			return err
		}
	}
	checkInterval := o.CheckInterval
	if checkInterval <= 0 {
		checkInterval = 60 * time.Second
	}

	managed := newManagedAgent()
	defer managed.wipe()

	// Issue initial certificate before opening the socket so startup errors
	// fail fast and loudly.
	priv, cert, resp, err := a.issueRoleInMemory(ctx, o.Principals, o.TTL)
	if err != nil {
		return err
	}
	if err := managed.replace(priv, cert, "osmium "+resp.CertID); err != nil {
		clear(priv)
		return err
	}

	ln, err := prepareUnixSocket(sockPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}()

	log.Info("osmium ssh-agent started",
		"socket", sockPath,
		"cert_id", resp.CertID,
		"principals", resp.Principals,
		"valid_before", resp.ValidBefore.Format(time.RFC3339),
	)
	if o.OnReady != nil {
		o.OnReady(sockPath, cert)
	}

	stopLn := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stopLn()

	var connWG sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connWG.Add(1)
			go func(c net.Conn) {
				defer connWG.Done()
				defer c.Close()
				_ = agent.ServeAgent(managed, c)
			}(conn)
		}
	}()

	renewTimer := time.NewTimer(computeRenewDelay(cert, o.RenewBefore))
	defer renewTimer.Stop()
	checkTicker := time.NewTicker(checkInterval)
	defer checkTicker.Stop()

	wipeOnce := func(reason string) {
		if managed.currentCert() == nil {
			return
		}
		managed.wipe()
		log.Warn("wiped in-memory ssh certificate", "reason", reason)
		if o.OnWipe != nil {
			o.OnWipe(reason)
		}
	}

	revoked := false
	for {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			<-acceptDone
			connWG.Wait()
			return nil

		case <-checkTicker.C:
			if revoked {
				continue
			}
			if cur := managed.currentCert(); cur != nil && time.Now().After(time.Unix(int64(cur.ValidBefore), 0)) {
				wipeOnce("certificate_expired")
			}
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := a.Me(checkCtx)
			cancel()
			if err != nil && isAuthRevokedError(err) {
				revoked = true
				wipeOnce("credentials_revoked")
			}

		case <-renewTimer.C:
			if revoked {
				continue
			}
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			nPriv, nCert, nResp, err := a.issueRoleInMemory(rctx, o.Principals, o.TTL)
			cancel()
			if err != nil {
				if isAuthRevokedError(err) {
					revoked = true
					wipeOnce("renewal_denied")
					continue
				}
				// Transient CA/network failure: wipe if current cert expired,
				// otherwise retry before expiry.
				retryDelay := 15 * time.Second
				if cur := managed.currentCert(); cur != nil {
					rem := time.Until(time.Unix(int64(cur.ValidBefore), 0))
					if rem <= 0 {
						wipeOnce("certificate_expired")
					} else if rem/3 < retryDelay {
						retryDelay = max(rem/3, time.Second)
					}
				}
				log.Warn("certificate renewal failed; will retry", "err", err, "retry_in", retryDelay)
				renewTimer.Reset(retryDelay)
				continue
			}
			if err := managed.replace(nPriv, nCert, "osmium "+nResp.CertID); err != nil {
				clear(nPriv)
				log.Error("failed to swap renewed certificate", "err", err)
				renewTimer.Reset(10 * time.Second)
				continue
			}
			log.Info("rotated key and renewed ssh certificate",
				"cert_id", nResp.CertID,
				"principals", nResp.Principals,
				"valid_before", nResp.ValidBefore.Format(time.RFC3339),
			)
			if o.OnRenew != nil {
				o.OnRenew(nCert)
			}
			renewTimer.Reset(computeRenewDelay(nCert, o.RenewBefore))
		}
	}
}
