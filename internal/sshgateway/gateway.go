// Package sshgateway is the Server-side SSH client: it creates the per-attempt
// ephemeral key, pairs it with the issued certificate and authenticates to the
// target sshd over an already acknowledged smux stream, verifying the pinned
// host key.
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

// ErrHostKeyMismatch is returned when the target presents an unpinned key.
var ErrHostKeyMismatch = errors.New("ssh host key does not match the pinned identity")

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
	HostID   string
	Login    string
	HostKeys []ssh.PublicKey
}

func hostKeyAlgorithms(keys []ssh.PublicKey) []string {
	var algs []string
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

// HostKeyCallback accepts only the pinned plain host keys.
func HostKeyCallback(pins []ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
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
	if len(t.HostKeys) == 0 {
		return nil, errors.New("no pinned host keys")
	}
	certSigner, err := ssh.NewCertSigner(cert, key.Signer)
	if err != nil {
		return nil, fmt.Errorf("pair certificate: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:              t.Login,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback:   HostKeyCallback(t.HostKeys),
		HostKeyAlgorithms: hostKeyAlgorithms(t.HostKeys),
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
