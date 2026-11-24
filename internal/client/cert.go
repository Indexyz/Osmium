package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// CertOptions configures direct certificate issuance or renewal for local
// OpenSSH workflows (osmium cert login / sign / ensure).
type CertOptions struct {
	Mode         string        // "host" or "role"
	HostID       string        // required when Mode == "host"
	Login        string        // required when Mode == "host" (or auto-resolved)
	Principals   []string      // optional narrowing subset when Mode == "role"
	TTL          time.Duration // optional; strictly server-capped
	OutDir       string        // output directory when writing files
	KeyName      string        // base filename (default "id")
	LoadAgent    bool          // load into system SSH_AUTH_SOCK when available
	WriteKey     bool          // write private key + cert to OutDir (0600)
	ReuseValid   bool          // when true, skip signing if existing cert on disk has >= MinRemaining left
	MinRemaining time.Duration // threshold for ReuseValid
}

// CertResult describes an issued or reused local SSH certificate.
type CertResult struct {
	CertID         string
	Mode           string
	Principals     []string
	ValidAfter     time.Time
	ValidBefore    time.Time
	SourceAddress  string
	SSHAddress     string
	KeyPath        string
	CertPath       string
	KnownHostsPath string
	AgentLoaded    bool
	Reused         bool
}

// DefaultCertDir returns the default private directory for storing short-lived
// direct certificates (e.g. <configDir>/certs/<subdir>).
func DefaultCertDir(subdir string) (string, error) {
	base, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "certs", subdir), nil
}

// IssueCert obtains (or reuses when ReuseValid is set) a direct SSH certificate.
// Every fresh issuance uses a brand new ephemeral Ed25519 key pair.
func (a *API) IssueCert(ctx context.Context, o CertOptions) (*CertResult, error) {
	if o.Mode != "host" && o.Mode != "role" {
		return nil, fmt.Errorf("invalid cert mode %q (expected host or role)", o.Mode)
	}
	if o.KeyName == "" {
		o.KeyName = "id"
	}
	if o.Mode == "host" && o.Login == "" {
		login, err := a.ResolveLogin(ctx, o.HostID, o.Login)
		if err != nil {
			return nil, err
		}
		o.Login = login
	}

	sock := os.Getenv("SSH_AUTH_SOCK")
	useAgent := o.LoadAgent && sock != ""
	writeFiles := o.WriteKey || !useAgent || o.OutDir != ""
	outDir := o.OutDir
	if writeFiles && outDir == "" {
		sub := "role"
		if o.Mode == "host" {
			sub = filepath.Join("hosts", o.HostID+"_"+o.Login)
		}
		var err error
		outDir, err = DefaultCertDir(sub)
		if err != nil {
			return nil, err
		}
	}

	keyPath := filepath.Join(outDir, o.KeyName)
	pubPath := keyPath + ".pub"
	certPath := keyPath + "-cert.pub"
	khPath := filepath.Join(outDir, "known_hosts")

	if o.ReuseValid && writeFiles {
		minRem := o.MinRemaining
		if minRem <= 0 {
			if o.Mode == "host" {
				minRem = 20 * time.Second
			} else {
				minRem = 5 * time.Minute
			}
		}
		if reused := checkExistingCert(keyPath, certPath, o.Principals, minRem); reused != nil {
			reused.Mode = o.Mode
			reused.KeyPath = keyPath
			reused.CertPath = certPath
			if _, err := os.Stat(khPath); err == nil {
				reused.KnownHostsPath = khPath
			}
			return reused, nil
		}
	}

	// Always generate a fresh ephemeral Ed25519 key per certificate issuance.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(priv)
	sshPub, _ := ssh.NewPublicKey(pub)

	req := DirectCertRequest{
		Mode:       o.Mode,
		HostID:     o.HostID,
		LoginUser:  o.Login,
		Principals: o.Principals,
		PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	}
	if o.TTL > 0 {
		req.TTL = o.TTL.String()
	}
	resp, err := a.IssueDirectCert(ctx, req)
	if err != nil {
		return nil, err
	}
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	cert, ok := certKey.(*ssh.Certificate)
	if err != nil || !ok || !bytes.Equal(cert.Key.Marshal(), sshPub.Marshal()) {
		return nil, errors.New("server returned a certificate for a different key")
	}

	res := &CertResult{
		CertID:        resp.CertID,
		Mode:          resp.Mode,
		Principals:    resp.Principals,
		ValidAfter:    resp.ValidAfter,
		ValidBefore:   resp.ValidBefore,
		SourceAddress: resp.SourceAddress,
		SSHAddress:    resp.SSHAddress,
	}

	if writeFiles {
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return nil, err
		}
		_ = os.Chmod(outDir, 0o700)
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return nil, err
		}
		if err := writeAtomic0600(keyPath, pem.EncodeToMemory(block)); err != nil {
			return nil, err
		}
		if err := writeAtomic0600(pubPath, ssh.MarshalAuthorizedKey(sshPub)); err != nil {
			return nil, err
		}
		if err := writeAtomic0600(certPath, ssh.MarshalAuthorizedKey(cert)); err != nil {
			return nil, err
		}
		res.KeyPath = keyPath
		res.CertPath = certPath
		if o.Mode == "host" && (len(resp.HostKeys) > 0 || len(resp.HostCAs) > 0) {
			if hks, cas, err := parseHostTrust(resp.HostKeys, resp.HostCAs); err == nil {
				_, khContent := formatKnownHosts(o.HostID, hks, cas, resp.HostCertPrincipals)
				if err := writeAtomic0600(khPath, []byte(khContent)); err != nil {
					return nil, err
				}
				res.KnownHostsPath = khPath
			}
		}
	}

	if useAgent {
		if err := loadIntoSystemAgent(sock, priv, cert, "osmium "+resp.CertID); err != nil {
			return nil, err
		}
		res.AgentLoaded = true
	}
	return res, nil
}

func writeAtomic0600(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, path)
}

func checkExistingCert(keyPath, certPath string, wantPrincipals []string, minRemaining time.Duration) *CertResult {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok || !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil
	}
	validBefore := time.Unix(int64(cert.ValidBefore), 0).UTC()
	if time.Until(validBefore) < minRemaining {
		return nil
	}
	if len(wantPrincipals) > 0 {
		for _, wp := range wantPrincipals {
			if !slices.Contains(cert.ValidPrincipals, wp) {
				return nil
			}
		}
	}
	return &CertResult{
		CertID:        cert.KeyId,
		Principals:    slices.Clone(cert.ValidPrincipals),
		ValidAfter:    time.Unix(int64(cert.ValidAfter), 0).UTC(),
		ValidBefore:   validBefore,
		SourceAddress: cert.CriticalOptions["source-address"],
		Reused:        true,
	}
}

func loadIntoSystemAgent(sock string, priv ed25519.PrivateKey, cert *ssh.Certificate, comment string) error {
	ac, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("ssh-agent: %w (use --no-agent to write key files instead)", err)
	}
	defer ac.Close()
	ag := agent.NewClient(ac)
	life := time.Until(time.Unix(int64(cert.ValidBefore), 0)) + 30*time.Second
	if life < time.Minute {
		life = time.Minute
	}
	if life > 24*time.Hour {
		life = 24 * time.Hour
	}
	secs := uint32(life.Seconds())
	for _, k := range []agent.AddedKey{
		{PrivateKey: priv, LifetimeSecs: secs, Comment: comment},
		{PrivateKey: priv, Certificate: cert, LifetimeSecs: secs, Comment: comment},
	} {
		if err := ag.Add(k); err != nil {
			return fmt.Errorf("ssh-agent: add key: %w (use --no-agent to skip)", err)
		}
	}
	return nil
}

// SSHConfigOptions controls OpenSSH client config generation.
type SSHConfigOptions struct {
	Labels         []string // optional label filters (key=value)
	HostPrefix     string   // optional prefix on generated Host aliases
	UseAgent       bool     // point generated hosts at osmium ssh-agent socket instead of Match exec
	AgentSocket    string   // defaults to DefaultAgentSocketPath() when UseAgent is true
	MatchPattern   string   // optional wildcard Host pattern (e.g. "*.prod.internal") for agent/role mode
	KnownHostsPath string   // defaults to <configDir>/known_hosts
	OsmiumBinary   string   // defaults to os.Executable()
}

// GenerateSSHConfig writes the server's trusted Host CAs to KnownHostsPath (if
// any are configured) and returns an OpenSSH config snippet covering visible
// direct/dual-mode hosts and/or a wildcard role-agent pattern.
func (a *API) GenerateSSHConfig(ctx context.Context, o SSHConfigOptions) (string, error) {
	cfgDir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	if o.KnownHostsPath == "" {
		o.KnownHostsPath = filepath.Join(cfgDir, "known_hosts")
	}
	if o.OsmiumBinary == "" {
		self, err := os.Executable()
		if err != nil {
			return "", err
		}
		o.OsmiumBinary = self
	}
	if o.UseAgent && o.AgentSocket == "" {
		sock, err := DefaultAgentSocketPath()
		if err != nil {
			return "", err
		}
		o.AgentSocket = sock
	}

	hostCAs, err := a.HostCAs(ctx)
	if err != nil {
		return "", err
	}
	hosts, err := a.Hosts(ctx, o.Labels)
	if err != nil {
		return "", err
	}

	hasHostCA := len(hostCAs) > 0
	if hasHostCA {
		if err := os.MkdirAll(filepath.Dir(o.KnownHostsPath), 0o700); err != nil {
			return "", err
		}
		var kh strings.Builder
		kh.WriteString("# Generated by osmium ssh-config — trusted SSH Host CAs\n")
		for _, line := range hostCAs {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			kh.WriteString("@cert-authority * " + line + "\n")
		}
		if err := writeAtomic0600(o.KnownHostsPath, []byte(kh.String())); err != nil {
			return "", err
		}
	}

	var b strings.Builder
	b.WriteString("# Generated by osmium ssh-config\n")
	b.WriteString("# Server: " + a.Creds.Server + "\n\n")

	if o.UseAgent && o.MatchPattern != "" {
		b.WriteString("Host " + o.MatchPattern + "\n")
		b.WriteString("    IdentityAgent " + quoteSSHConfigPath(o.AgentSocket) + "\n")
		if hasHostCA {
			b.WriteString("    UserKnownHostsFile " + quoteSSHConfigPath(o.KnownHostsPath) + "\n")
			b.WriteString("    StrictHostKeyChecking yes\n")
		}
		b.WriteString("    PasswordAuthentication no\n")
		b.WriteString("    KbdInteractiveAuthentication no\n\n")
	}

	directCount := 0
	tunnelCount := 0
	for _, h := range hosts {
		if h.ConnectionMode != "direct" && h.ConnectionMode != "both" {
			tunnelCount++
			continue
		}
		if h.SSHAddress == "" {
			continue
		}
		addrHost, addrPort, err := net.SplitHostPort(h.SSHAddress)
		if err != nil {
			continue
		}
		directCount++
		alias := o.HostPrefix + h.ID
		b.WriteString("Host " + alias + "\n")
		b.WriteString("    HostName " + addrHost + "\n")
		b.WriteString("    Port " + addrPort + "\n")
		if len(h.AllowedLoginUsers) == 1 {
			b.WriteString("    User " + h.AllowedLoginUsers[0] + "\n")
		}
		if hasHostCA {
			b.WriteString("    UserKnownHostsFile " + quoteSSHConfigPath(o.KnownHostsPath) + "\n")
			b.WriteString("    StrictHostKeyChecking yes\n")
		}
		b.WriteString("    PasswordAuthentication no\n")
		b.WriteString("    KbdInteractiveAuthentication no\n")
		if o.UseAgent {
			b.WriteString("    IdentityAgent " + quoteSSHConfigPath(o.AgentSocket) + "\n\n")
			continue
		}
		certDir := filepath.Join(cfgDir, "certs", "hosts", h.ID)
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("Match host %s exec \"%s cert ensure --quiet --out %s --login %%r %s\"\n",
			alias,
			escapeExecArg(o.OsmiumBinary),
			escapeExecArg(certDir),
			h.ID,
		))
		b.WriteString("    IdentityFile " + quoteSSHConfigPath(filepath.Join(certDir, "id")) + "\n")
		b.WriteString("    CertificateFile " + quoteSSHConfigPath(filepath.Join(certDir, "id-cert.pub")) + "\n")
		if !hasHostCA {
			b.WriteString("    UserKnownHostsFile " + quoteSSHConfigPath(filepath.Join(certDir, "known_hosts")) + "\n")
			b.WriteString("    HostKeyAlias osmium-" + h.ID + "\n")
			b.WriteString("    StrictHostKeyChecking yes\n")
		}
		b.WriteString("    IdentitiesOnly yes\n")
		b.WriteString("    IdentityAgent none\n\n")
	}

	if directCount == 0 && o.MatchPattern == "" {
		b.WriteString("# No direct/dual-mode hosts found in your policy.\n")
	}
	if tunnelCount > 0 {
		b.WriteString(fmt.Sprintf("# %d tunnel-only host(s) omitted; connect to them via: osmium ssh <host-id>\n", tunnelCount))
	}
	return b.String(), nil
}

func quoteSSHConfigPath(p string) string {
	p = sshToken(p)
	if strings.ContainsAny(p, " \t\"") {
		return `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
	}
	return p
}

func escapeExecArg(p string) string {
	p = strings.ReplaceAll(p, `\`, `/`)
	p = sshToken(p)
	return `'` + strings.ReplaceAll(p, `'`, `'\''`) + `'`
}
