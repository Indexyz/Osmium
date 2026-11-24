// Package sshgateway is the Server-side SSH client: it creates the per-attempt
// ephemeral key, pairs it with the issued certificate and authenticates to the
// target sshd over an already acknowledged smux stream, strictly verifying
// either pinned host keys or an SSH Host Certificate signed by a trusted Host CA.
package sshgateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrHostKeyMismatch is returned when the target presents an unpinned key or an
// invalid/untrusted host certificate.
var ErrHostKeyMismatch = errors.New("ssh host key does not match the pinned identity or trusted host CA")

// EphemeralKey is a per-attempt private key held only in memory.
type EphemeralKey struct {
	Signer ssh.Signer
}

// NewEphemeralKey creates a fresh Ed25519 key.
func NewEphemeralKey() (*EphemeralKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return &EphemeralKey{Signer: s}, nil
}

// PublicKey returns the SSH public key.
func (k *EphemeralKey) PublicKey() ssh.PublicKey { return k.Signer.PublicKey() }

// Fingerprint returns the SHA256 fingerprint of a public key.
func Fingerprint(k ssh.PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Target is the trusted SSH destination for one attempt.
type Target struct {
	HostID             string
	Login              string
	HostKeys           []ssh.PublicKey
	HostCAs            []ssh.PublicKey
	HostCertPrincipals []string // defaults to [HostID] when empty
}

func hostKeyAlgorithms(keys, hostCAs []ssh.PublicKey) []string {
	var algs []string
	if len(hostCAs) > 0 {
		algs = append(algs,
			ssh.CertAlgoED25519v01,
			ssh.CertAlgoECDSA256v01,
			ssh.CertAlgoECDSA384v01,
			ssh.CertAlgoECDSA521v01,
			ssh.CertAlgoRSASHA512v01,
			ssh.CertAlgoRSASHA256v01,
		)
	}
	for _, k := range keys {
		switch k.Type() {
		case ssh.KeyAlgoRSA:
			algs = append(algs, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		default:
			algs = append(algs, k.Type())
		}
	}
	return slices.Compact(algs)
}

// HostKeyCallback accepts only pinned plain host keys.
func HostKeyCallback(pins []ssh.PublicKey) ssh.HostKeyCallback {
	return HostIdentityCallback(pins, nil, nil)
}

// HostIdentityCallback verifies the target sshd's identity against pinned plain
// host keys and/or trusted SSH Host CA public keys (with explicit host
// principal and validity enforcement). Never falls open.
func HostIdentityCallback(pins, hostCAs []ssh.PublicKey, principals []string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if cert, ok := key.(*ssh.Certificate); ok {
			if len(hostCAs) == 0 || len(principals) == 0 {
				return ErrHostKeyMismatch
			}
			if cert.CertType != ssh.HostCert {
				return ErrHostKeyMismatch
			}
			trustedCA := false
			for _, caKey := range hostCAs {
				if bytes.Equal(caKey.Marshal(), cert.SignatureKey.Marshal()) {
					trustedCA = true
					break
				}
			}
			if !trustedCA {
				return ErrHostKeyMismatch
			}
			checker := &ssh.CertChecker{
				IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
					for _, caKey := range hostCAs {
						if bytes.Equal(caKey.Marshal(), auth.Marshal()) {
							return true
						}
					}
					return false
				},
			}
			for _, principal := range principals {
				if err := checker.CheckCert(principal, cert); err == nil {
					return nil
				}
			}
			return ErrHostKeyMismatch
		}
		for _, p := range pins {
			if bytes.Equal(p.Marshal(), key.Marshal()) {
				return nil
			}
		}
		return ErrHostKeyMismatch
	}
}

// Connect performs the SSH handshake and certificate authentication over conn
// (one smux stream). The handshake deadline applies to conn only and is
// cleared on success; ctx cancellation aborts the handshake.
func Connect(ctx context.Context, conn net.Conn, t Target, key *EphemeralKey, cert *ssh.Certificate, timeout time.Duration) (*ssh.Client, error) {
	if len(t.HostKeys) == 0 && len(t.HostCAs) == 0 {
		return nil, errors.New("no pinned host keys or trusted host CAs")
	}
	principals := t.HostCertPrincipals
	if len(principals) == 0 && t.HostID != "" {
		principals = []string{t.HostID}
	}
	certSigner, err := ssh.NewCertSigner(cert, key.Signer)
	if err != nil {
		return nil, fmt.Errorf("pair certificate: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:              t.Login,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback:   HostIdentityCallback(t.HostKeys, t.HostCAs, principals),
		HostKeyAlgorithms: hostKeyAlgorithms(t.HostKeys, t.HostCAs),
		ClientVersion:     "SSH-2.0-Osmium",
		Timeout:           timeout,
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(done)
	})
	c, chans, reqs, err := ssh.NewClientConn(conn, t.HostID, cfg)
	if !stop() {
		<-done
		if err == nil {
			_ = c.Close()
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// Shell opens one PTY session running the login shell.
func Shell(client *ssh.Client, rows, cols int) (*ssh.Session, error) {
	s, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := s.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}
