// Package client implements the osmium CLI: login against the Server, list
// hosts and run the user's own OpenSSH client through a native tunnel, with
// the per-connection key and certificate loaded into the user's ssh-agent.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials are stored in the user's config directory with mode 0600.
type Credentials struct {
	Server    string    `json:"server"`
	CAFile    string    `json:"ca_file,omitempty"`
	Token     string    `json:"access_token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
	} `json:"user"`
}

// ConfigDir returns the local osmium client configuration directory.
// OSMIUM_CONFIG overrides the default OS user config location.
func ConfigDir() (string, error) {
	dir := os.Getenv("OSMIUM_CONFIG")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "osmium")
	}
	return dir, nil
}

// CredentialsPath returns the default credentials file location. OSMIUM_CONFIG
// overrides the directory.
func CredentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

// Load reads the stored credentials.
func Load() (*Credentials, error) {
	p, err := CredentialsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("not logged in; run: osmium login --server https://...")
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, errors.New("login expired; run: osmium login")
	}
	return &c, nil
}

// Save writes credentials with owner-only permissions.
func (c *Credentials) Save() error {
	p, err := CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Remove deletes the stored credentials.
func Remove() error {
	p, err := CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// CheckServerURL requires https, except plain http to a loopback host for
// local development.
func CheckServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return nil, errors.New("server must be an origin such as https://ssh.example.com")
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return u, nil
		}
	}
	return nil, errors.New("server must use https (http is allowed for loopback only)")
}

// HTTPClient builds an HTTP client trusting the optional CA file. Redirects
// are not followed so a token is never forwarded elsewhere.
func HTTPClient(caFile string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca file contains no certificates")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// API is an authenticated Server client.
type API struct {
	Creds *Credentials
	HTTP  *http.Client
}

// NewAPI loads credentials and builds a client.
func NewAPI() (*API, error) {
	c, err := Load()
	if err != nil {
		return nil, err
	}
	if _, err := CheckServerURL(c.Server); err != nil {
		return nil, err
	}
	h, err := HTTPClient(c.CAFile)
	if err != nil {
		return nil, err
	}
	return &API{Creds: c, HTTP: h}, nil
}

// APIError is a Server error response.
type APIError struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s (%d %s)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("server returned %d %s", e.Status, e.Code)
}

func (a *API) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Creds.Server+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Creds.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(e)
		if resp.StatusCode == http.StatusUnauthorized {
			e.Message = "login expired or revoked; run: osmium login"
		}
		return e
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}

// Host is a host visible to the user.
type Host struct {
	ID                string            `json:"id"`
	DisplayName       string            `json:"display_name"`
	ConnectionMode    string            `json:"connection_mode"`
	SSHAddress        string            `json:"ssh_address,omitempty"`
	Status            string            `json:"status"`
	PolicyLabels      map[string]string `json:"policy_labels"`
	AllowedLoginUsers []string          `json:"allowed_login_users"`
}

// DirectCertRequest requests a direct (agentless) SSH user certificate.
type DirectCertRequest struct {
	Mode       string   `json:"mode"`                 // "host" or "role"
	HostID     string   `json:"host_id,omitempty"`    // required when mode == "host"
	LoginUser  string   `json:"login_user,omitempty"` // required when mode == "host"
	Principals []string `json:"principals,omitempty"` // optional subset when mode == "role"
	TTL        string   `json:"ttl,omitempty"`        // optional Go duration; server-capped
	PublicKey  string   `json:"public_key"`           // ephemeral ed25519/ecdsa public key
}

// DirectCertResponse is the server response from POST /api/v1/direct-certs.
type DirectCertResponse struct {
	CertID             string    `json:"cert_id"`
	Mode               string    `json:"mode"`
	Certificate        string    `json:"certificate"`
	KeyID              string    `json:"key_id"`
	Serial             string    `json:"serial"`
	Principals         []string  `json:"principals"`
	ValidAfter         time.Time `json:"valid_after"`
	ValidBefore        time.Time `json:"valid_before"`
	SourceAddress      string    `json:"source_address,omitempty"`
	SSHAddress         string    `json:"ssh_address,omitempty"`
	HostKeys           []string  `json:"host_keys,omitempty"`
	HostCAs            []string  `json:"host_cas,omitempty"`
	HostCertPrincipals []string  `json:"host_cert_principals,omitempty"`
}

// MeResponse is the response from GET /api/v1/me.
type MeResponse struct {
	User struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
	} `json:"user"`
	IsAdmin bool `json:"is_admin"`
}

// HostPageQuery filters and paginates visible hosts.
type HostPageQuery struct {
	Labels []string
	Query  string
	Status string
	Cursor string
	Limit  int
}

// HostPage is one paginated page from GET /api/v1/hosts.
type HostPage struct {
	Items      []Host `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Total      int    `json:"total"`
}

// HostsPage fetches a single page of visible hosts.
func (a *API) HostsPage(ctx context.Context, opt HostPageQuery) (HostPage, error) {
	q := url.Values{}
	for _, l := range opt.Labels {
		q.Add("label", l)
	}
	if opt.Query != "" {
		q.Set("q", opt.Query)
	}
	if opt.Status != "" {
		q.Set("status", opt.Status)
	}
	if opt.Cursor != "" {
		q.Set("cursor", opt.Cursor)
	}
	if opt.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", opt.Limit))
	}
	path := "/api/v1/hosts"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out HostPage
	if err := a.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return HostPage{}, err
	}
	return out, nil
}

// Hosts lists all matching visible hosts by walking cursor pages (avoids the
// 4 MiB single-response cap on 50k+ host fleets).
func (a *API) Hosts(ctx context.Context, labels []string) ([]Host, error) {
	var all []Host
	cursor := ""
	for {
		page, err := a.HostsPage(ctx, HostPageQuery{Labels: labels, Cursor: cursor, Limit: 500})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextCursor == "" || len(page.Items) == 0 {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

// FindHost looks up a single host by exact ID without pulling the full fleet.
func (a *API) FindHost(ctx context.Context, hostID string) (*Host, error) {
	cursor := ""
	for {
		page, err := a.HostsPage(ctx, HostPageQuery{Query: hostID, Cursor: cursor, Limit: 50})
		if err != nil {
			return nil, err
		}
		for i := range page.Items {
			if page.Items[i].ID == hostID {
				h := page.Items[i]
				return &h, nil
			}
		}
		if page.NextCursor == "" || len(page.Items) == 0 {
			return nil, fmt.Errorf("host %s not found or not accessible", hostID)
		}
		cursor = page.NextCursor
	}
}

// IssueDirectCert requests a short-lived direct SSH certificate for an
// ephemeral public key from POST /api/v1/direct-certs.
func (a *API) IssueDirectCert(ctx context.Context, req DirectCertRequest) (*DirectCertResponse, error) {
	var out DirectCertResponse
	if err := a.do(ctx, http.MethodPost, "/api/v1/direct-certs", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HostCAs fetches the server's trusted SSH Host CA public keys.
func (a *API) HostCAs(ctx context.Context) ([]string, error) {
	var out struct {
		HostCAPublicKeys []string `json:"host_ca_public_keys"`
	}
	if err := a.do(ctx, http.MethodGet, "/api/v1/host-cas", nil, &out); err != nil {
		return nil, err
	}
	return out.HostCAPublicKeys, nil
}

// Me validates the active credentials against GET /api/v1/me.
func (a *API) Me(ctx context.Context) (*MeResponse, error) {
	var out MeResponse
	if err := a.do(ctx, http.MethodGet, "/api/v1/me", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Logout revokes the token on the Server.
func (a *API) Logout(ctx context.Context) error {
	return a.do(ctx, http.MethodPost, "/api/v1/cli/logout", nil, nil)
}
