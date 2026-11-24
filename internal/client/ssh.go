package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/indexyz/osmium/internal/protocol"
)

// SSHOptions configures a native SSH connection.
type SSHOptions struct {
	HostID string
	Login  string // empty: use the only allowed login, if there is exactly one
	// Args are passed to ssh after the destination (remote command, or
	// further ssh options).
	Args []string
	// SSHBinary defaults to "ssh".
	SSHBinary string
	// ProxyCommand is the argv of the stdio helper that connects to a Unix
	// socket given as the last argument. Defaults to [<this binary>, "proxy-connect"].
	ProxyCommand []string
	// NoAgent writes the private key to a private temp file instead of
	// loading it into the ssh-agent at SSH_AUTH_SOCK.
	NoAgent bool
	// Direct forces direct (agentless) certificate mode instead of using the
	// Agent tunnel when connecting to a direct or dual-mode host.
	Direct bool

	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Verbose        bool
}

type nativeSession struct {
	ID         string `json:"id"`
	TunnelPath string `json:"tunnel_path"`
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// sshToken escapes % for ssh_config token expansion.
func sshToken(s string) string { return strings.ReplaceAll(s, "%", "%%") }

// ResolveLogin picks the login for hostID when none was given, querying only
// matching host entries instead of pulling the full fleet directory.
func (a *API) ResolveLogin(ctx context.Context, hostID, login string) (string, error) {
	if login != "" {
		return login, nil
	}
	h, err := a.FindHost(ctx, hostID)
	if err != nil {
		return "", err
	}
	if len(h.AllowedLoginUsers) == 1 {
		return h.AllowedLoginUsers[0], nil
	}
	return "", fmt.Errorf("host %s allows several logins (%s); use login@%s", hostID, strings.Join(h.AllowedLoginUsers, ", "), hostID)
}

func nullKnownHostsPath() string {
	if runtime.GOOS == "windows" {
		return "none"
	}
	return "/dev/null"
}

func parseHostTrust(rawHostKeys, rawHostCAs []string) ([]ssh.PublicKey, []ssh.PublicKey, error) {
	var hostKeys []ssh.PublicKey
	for _, k := range rawHostKeys {
		hk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			return nil, nil, errors.New("server returned an invalid host key")
		}
		if _, isCert := hk.(*ssh.Certificate); isCert {
			return nil, nil, errors.New("server returned a certificate as host key")
		}
		hostKeys = append(hostKeys, hk)
	}
	var hostCAs []ssh.PublicKey
	for _, k := range rawHostCAs {
		caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			return nil, nil, errors.New("server returned an invalid host CA key")
		}
		if _, isCert := caKey.(*ssh.Certificate); isCert {
			return nil, nil, errors.New("server returned a certificate as host CA")
		}
		hostCAs = append(hostCAs, caKey)
	}
	if len(hostKeys) == 0 && len(hostCAs) == 0 {
		return nil, nil, errors.New("server returned neither pinned host keys nor host CAs")
	}
	return hostKeys, hostCAs, nil
}

func formatKnownHosts(hostID string, hostKeys, hostCAs []ssh.PublicKey, hostCertPrincipals []string) (alias string, content string) {
	alias = "osmium-" + hostID
	if len(hostCAs) > 0 {
		// When verifying a Host Certificate, OpenSSH checks the HostKeyAlias
		// against the certificate's principals.
		alias = hostID
		if len(hostCertPrincipals) > 0 && hostCertPrincipals[0] != "" {
			alias = hostCertPrincipals[0]
		}
	}
	var kh strings.Builder
	for _, k := range hostKeys {
		kh.WriteString(alias + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n")
	}
	if len(hostCAs) > 0 {
		principals := alias
		if len(hostCertPrincipals) > 0 {
			principals = strings.Join(hostCertPrincipals, ",")
		}
		for _, caKey := range hostCAs {
			kh.WriteString("@cert-authority " + principals + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caKey))) + "\n")
		}
	}
	return alias, kh.String()
}

// SSH runs the user's OpenSSH client against hostID (automatically selecting
// direct certificate mode for direct hosts or dual-mode hosts whose agent is
// offline, or native tunnel mode otherwise) and returns ssh's exit code.
func (a *API) SSH(ctx context.Context, o SSHOptions) (int, error) {
	if o.SSHBinary == "" {
		o.SSHBinary = "ssh"
	}
	if o.Stdin == nil {
		o.Stdin, o.Stdout, o.Stderr = os.Stdin, os.Stdout, os.Stderr
	}
	logf := func(format string, args ...any) {
		if o.Verbose {
			fmt.Fprintf(o.Stderr, "osmium: "+format+"\n", args...)
		}
	}
	sshPath, err := exec.LookPath(o.SSHBinary)
	if err != nil {
		return 0, fmt.Errorf("OpenSSH client not found: %w", err)
	}

	useDirect := o.Direct
	login := o.Login
	if !useDirect {
		if host, herr := a.FindHost(ctx, o.HostID); herr == nil {
			if login == "" {
				if len(host.AllowedLoginUsers) == 1 {
					login = host.AllowedLoginUsers[0]
				} else {
					return 0, fmt.Errorf("host %s allows several logins (%s); use login@%s", o.HostID, strings.Join(host.AllowedLoginUsers, ", "), o.HostID)
				}
			}
			if host.ConnectionMode == "direct" || (host.ConnectionMode == "both" && host.Status != "ready") {
				useDirect = true
			}
		} else if login == "" {
			return 0, herr
		}
	} else if login == "" {
		login, err = a.ResolveLogin(ctx, o.HostID, o.Login)
		if err != nil {
			return 0, err
		}
	}

	if useDirect {
		logf("connecting to %s via direct SSH certificate mode", o.HostID)
		return a.sshDirect(ctx, o, sshPath, login, logf)
	}

	if len(o.ProxyCommand) == 0 {
		self, err := os.Executable()
		if err != nil {
			return 0, err
		}
		o.ProxyCommand = []string{self, "proxy-connect"}
	}

	// One fresh key per connection attempt; it never leaves this machine.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, err
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	var sess nativeSession
	err = a.do(ctx, http.MethodPost, "/api/v1/native-sessions", map[string]string{
		"host_id": o.HostID, "login_user": login, "public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	}, &sess)
	if err != nil {
		return 0, err
	}
	logf("session %s created", sess.ID)

	ws, err := a.dialTunnel(ctx, sess.TunnelPath)
	if err != nil {
		return 0, err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)

	ready, err := waitReady(ctx, ws, logf)
	if err != nil {
		return 0, err
	}
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ready.Certificate))
	cert, ok := certKey.(*ssh.Certificate)
	if err != nil || !ok || string(cert.Key.Marshal()) != string(sshPub.Marshal()) {
		return 0, errors.New("server returned a certificate for a different key")
	}
	hostKeys, hostCAs, err := parseHostTrust(ready.HostKeys, ready.HostCAs)
	if err != nil {
		return 0, err
	}

	dir, err := os.MkdirTemp("", "osmium-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return 0, err
	}
	alias, khContent := formatKnownHosts(o.HostID, hostKeys, hostCAs, ready.HostCertPrincipals)
	khPath := filepath.Join(dir, "known_hosts")
	certPath := filepath.Join(dir, "id-cert.pub")
	if err := os.WriteFile(khPath, []byte(khContent), 0o600); err != nil {
		return 0, err
	}
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
		return 0, err
	}

	args := []string{}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if !o.NoAgent && sock != "" {
		ac, err := net.Dial("unix", sock)
		if err != nil {
			return 0, fmt.Errorf("ssh-agent: %w (use --no-agent to skip)", err)
		}
		defer ac.Close()
		ag := agent.NewClient(ac)
		life := time.Until(time.Unix(int64(cert.ValidBefore), 0)) + 30*time.Second
		life = min(max(life, time.Minute), 10*time.Minute)
		// Like ssh-add: the plain key plus its certificate, both time limited.
		// The agent drops them on its own after LifetimeSecs.
		for _, k := range []agent.AddedKey{
			{PrivateKey: priv, LifetimeSecs: uint32(life.Seconds()), Comment: "osmium " + sess.ID},
			{PrivateKey: priv, Certificate: cert, LifetimeSecs: uint32(life.Seconds()), Comment: "osmium " + sess.ID},
		} {
			if err := ag.Add(k); err != nil {
				_ = ag.Remove(sshPub)
				return 0, fmt.Errorf("ssh-agent: add key: %w (use --no-agent to skip)", err)
			}
		}
		defer func() { _ = ag.Remove(cert); _ = ag.Remove(sshPub) }()
		pubPath := filepath.Join(dir, "id.pub")
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
			return 0, err
		}
		// IdentityFile names a key whose private half is absent: ssh then
		// uses id.pub / id-cert.pub to select the matching agent identity.
		args = append(args, "-o", "IdentityFile="+sshToken(filepath.Join(dir, "id")))
		logf("certificate loaded into ssh-agent for %s", life.Round(time.Second))
	} else {
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return 0, err
		}
		keyPath := filepath.Join(dir, "id")
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
			return 0, err
		}
		args = append(args, "-o", "IdentityAgent=none", "-o", "IdentityFile="+sshToken(keyPath))
	}

	sockPath := filepath.Join(dir, "proxy.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return 0, err
	}
	defer ln.Close()

	proxy := make([]string, 0, len(o.ProxyCommand)+1)
	for _, p := range append(append([]string{}, o.ProxyCommand...), sockPath) {
		proxy = append(proxy, shQuote(p))
	}
	args = append(args,
		"-o", "ProxyCommand="+sshToken(strings.Join(proxy, " ")),
		"-o", "HostKeyAlias="+alias,
		"-o", "UserKnownHostsFile="+sshToken(khPath),
		"-o", "GlobalKnownHostsFile="+nullKnownHostsPath(),
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "CertificateFile="+sshToken(certPath),
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-l", login, o.HostID,
	)
	args = append(args, o.Args...)

	var exitMu sync.Mutex
	exitReason := ""
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reason := relay(ctx, ws, conn)
		exitMu.Lock()
		exitReason = reason
		exitMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, sshPath, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = o.Stdin, o.Stdout, o.Stderr
	runErr := cmd.Run()
	_ = ln.Close()
	ws.Close(websocket.StatusNormalClosure, "ssh exited")
	select {
	case <-relayDone:
	case <-time.After(5 * time.Second):
	}
	exitMu.Lock()
	reason := exitReason
	exitMu.Unlock()
	if reason != "" && reason != "client_closed" && reason != "remote_closed" {
		fmt.Fprintf(o.Stderr, "osmium: session ended: %s\n", reason)
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		return ee.ExitCode(), nil
	}
	if runErr != nil {
		return 0, runErr
	}
	return 0, nil
}

// sshDirect connects directly to an agentless sshd using a single-host short-lived
// certificate issued by POST /api/v1/direct-certs (no ProxyCommand or relay).
func (a *API) sshDirect(ctx context.Context, o SSHOptions, sshPath, login string, logf func(string, ...any)) (int, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, err
	}
	defer clear(priv)
	sshPub, _ := ssh.NewPublicKey(pub)

	resp, err := a.IssueDirectCert(ctx, DirectCertRequest{
		Mode:      "host",
		HostID:    o.HostID,
		LoginUser: login,
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	})
	if err != nil {
		return 0, err
	}
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	cert, ok := certKey.(*ssh.Certificate)
	if err != nil || !ok || string(cert.Key.Marshal()) != string(sshPub.Marshal()) {
		return 0, errors.New("server returned a certificate for a different key")
	}
	targetHost, targetPort, err := net.SplitHostPort(resp.SSHAddress)
	if err != nil {
		return 0, fmt.Errorf("server returned invalid ssh_address %q: %w", resp.SSHAddress, err)
	}
	hostKeys, hostCAs, err := parseHostTrust(resp.HostKeys, resp.HostCAs)
	if err != nil {
		return 0, err
	}
	logf("direct cert %s issued for %s (%s), valid until %s", resp.CertID, resp.SSHAddress, strings.Join(resp.Principals, ","), resp.ValidBefore.Local().Format(time.RFC3339))

	dir, err := os.MkdirTemp("", "osmium-direct-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return 0, err
	}
	alias, khContent := formatKnownHosts(o.HostID, hostKeys, hostCAs, resp.HostCertPrincipals)
	khPath := filepath.Join(dir, "known_hosts")
	certPath := filepath.Join(dir, "id-cert.pub")
	if err := os.WriteFile(khPath, []byte(khContent), 0o600); err != nil {
		return 0, err
	}
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
		return 0, err
	}

	args := []string{"-p", targetPort}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if !o.NoAgent && sock != "" {
		ac, err := net.Dial("unix", sock)
		if err != nil {
			return 0, fmt.Errorf("ssh-agent: %w (use --no-agent to skip)", err)
		}
		defer ac.Close()
		ag := agent.NewClient(ac)
		life := time.Until(time.Unix(int64(cert.ValidBefore), 0)) + 30*time.Second
		life = min(max(life, time.Minute), 10*time.Minute)
		for _, k := range []agent.AddedKey{
			{PrivateKey: priv, LifetimeSecs: uint32(life.Seconds()), Comment: "osmium " + resp.CertID},
			{PrivateKey: priv, Certificate: cert, LifetimeSecs: uint32(life.Seconds()), Comment: "osmium " + resp.CertID},
		} {
			if err := ag.Add(k); err != nil {
				_ = ag.Remove(sshPub)
				return 0, fmt.Errorf("ssh-agent: add key: %w (use --no-agent to skip)", err)
			}
		}
		defer func() { _ = ag.Remove(cert); _ = ag.Remove(sshPub) }()
		pubPath := filepath.Join(dir, "id.pub")
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
			return 0, err
		}
		args = append(args, "-o", "IdentityFile="+sshToken(filepath.Join(dir, "id")))
		logf("certificate loaded into ssh-agent for %s", life.Round(time.Second))
	} else {
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return 0, err
		}
		keyPath := filepath.Join(dir, "id")
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
			return 0, err
		}
		args = append(args, "-o", "IdentityAgent=none", "-o", "IdentityFile="+sshToken(keyPath))
	}

	args = append(args,
		"-o", "HostKeyAlias="+alias,
		"-o", "UserKnownHostsFile="+sshToken(khPath),
		"-o", "GlobalKnownHostsFile="+nullKnownHostsPath(),
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "CertificateFile="+sshToken(certPath),
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-l", login, targetHost,
	)
	args = append(args, o.Args...)

	cmd := exec.CommandContext(ctx, sshPath, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = o.Stdin, o.Stdout, o.Stderr
	runErr := cmd.Run()
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		return ee.ExitCode(), nil
	}
	if runErr != nil {
		return 0, runErr
	}
	return 0, nil
}

func (a *API) dialTunnel(ctx context.Context, path string) (*websocket.Conn, error) {
	if !strings.HasPrefix(path, "/api/v1/ssh-sessions/") {
		return nil, errors.New("invalid tunnel path from server")
	}
	u := "ws" + strings.TrimPrefix(a.Creds.Server, "http") + path
	hc := *a.HTTP
	hc.Timeout = 0
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(dctx, u, &websocket.DialOptions{
		HTTPClient:      &hc,
		HTTPHeader:      http.Header{"Authorization": {"Bearer " + a.Creds.Token}},
		Subprotocols:    []string{protocol.SubprotocolNative},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("open tunnel: server returned %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("open tunnel: %w", err)
	}
	if ws.Subprotocol() != protocol.SubprotocolNative {
		ws.CloseNow()
		return nil, errors.New("open tunnel: subprotocol not negotiated")
	}
	return ws, nil
}

func waitReady(ctx context.Context, ws *websocket.Conn, logf func(string, ...any)) (*protocol.NativeReady, error) {
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		typ, data, err := ws.Read(rctx)
		if err != nil {
			return nil, fmt.Errorf("waiting for session: %w", err)
		}
		if typ != websocket.MessageText {
			return nil, errors.New("unexpected binary data before ready")
		}
		m, err := protocol.DecodeNative(data)
		if err != nil {
			return nil, err
		}
		switch {
		case m.State != nil:
			logf("state %s", m.State.State)
		case m.Exit != nil:
			return nil, fmt.Errorf("session failed: %s", m.Exit.Reason)
		case m.Ready != nil:
			return m.Ready, nil
		}
	}
}

// relay copies between the ProxyCommand socket and the tunnel until either
// side ends; it returns the Server's exit reason if one was received.
func relay(ctx context.Context, ws *websocket.Conn, conn net.Conn) string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reason := ""
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if ws.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if typ == websocket.MessageBinary {
				if _, err := conn.Write(data); err != nil {
					return
				}
				continue
			}
			if m, err := protocol.DecodeNative(data); err == nil && m.Exit != nil {
				reason = m.Exit.Reason
				return
			}
		}
	}()
	<-done
	_ = conn.Close()
	cancel()
	<-done
	return reason
}

// ProxyConnect is the ProxyCommand helper: it bridges stdio to the Unix
// socket of the parent osmium process.
func ProxyConnect(sockPath string, stdin io.Reader, stdout io.Writer) error {
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		return err
	}
	defer c.Close()
	go func() {
		_, _ = io.Copy(c, stdin)
		if uc, ok := c.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	_, err = io.Copy(stdout, c)
	return err
}
