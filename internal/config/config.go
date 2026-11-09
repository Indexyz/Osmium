// Package config loads the Server and Agent JSON configuration files.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/indexyz/osmium/internal/tunnel"
)

// Duration is a time.Duration encoded as a Go duration string ("30s").
type Duration time.Duration

// UnmarshalJSON parses "10s" style strings.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON renders the duration string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Smux mirrors tunnel.MuxConfig; zero values fall back to defaults. Both
// ends must use identical values.
type Smux struct {
	MaxFrameSize      int      `json:"max_frame_size"`
	MaxReceiveBuffer  int      `json:"max_receive_buffer"`
	MaxStreamBuffer   int      `json:"max_stream_buffer"`
	KeepAliveInterval Duration `json:"keepalive_interval"`
	KeepAliveTimeout  Duration `json:"keepalive_timeout"`
}

// Mux converts to tunnel.MuxConfig.
func (s Smux) Mux() tunnel.MuxConfig {
	c := tunnel.DefaultMuxConfig()
	if s.MaxFrameSize > 0 {
		c.MaxFrameSize = s.MaxFrameSize
	}
	if s.MaxReceiveBuffer > 0 {
		c.MaxReceiveBuffer = s.MaxReceiveBuffer
	}
	if s.MaxStreamBuffer > 0 {
		c.MaxStreamBuffer = s.MaxStreamBuffer
	}
	if s.KeepAliveInterval > 0 {
		c.KeepAliveInterval = s.KeepAliveInterval.D()
	}
	if s.KeepAliveTimeout > 0 {
		c.KeepAliveTimeout = s.KeepAliveTimeout.D()
	}
	return c
}

// OIDC configures the identity provider.
type OIDC struct {
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	RedirectURL      string   `json:"redirect_url"`
	Scopes           []string `json:"scopes"`
	GroupsClaim      string   `json:"groups_claim"`
}

// CA configures step-ca.
type CA struct {
	URL                 string   `json:"url"`
	RootCAFile          string   `json:"root_ca_file"`
	ProvisionerName     string   `json:"provisioner_name"`
	JWKFile             string   `json:"jwk_file"`
	JWKPasswordFile     string   `json:"jwk_password_file"`
	Audience            string   `json:"audience"`
	SignPath            string   `json:"sign_path"`
	ValidBefore         string   `json:"valid_before"`
	Timeout             Duration `json:"timeout"`
	UserCAPublicKeyFile string   `json:"user_ca_public_key_file"`
	MaxCertLifetime     Duration `json:"max_cert_lifetime"`
	AllowedExtensions   []string `json:"allowed_extensions"`
}

// Sessions holds session policy knobs.
type Sessions struct {
	AttachTimeout      Duration `json:"attach_timeout"`
	SSHHandshake       Duration `json:"ssh_handshake"`
	MaxSessionDuration Duration `json:"max_session_duration"`
	MaxPerUser         int      `json:"max_per_user"`
	MaxTotal           int      `json:"max_total"`
	RevokeActive       *bool    `json:"revoke_active"`
}

// Server is the server configuration.
type Server struct {
	ServerID   string `json:"server_id"`
	Listen     string `json:"listen"`
	TLSCert    string `json:"tls_cert"`
	TLSKey     string `json:"tls_key"`
	PublicURL  string `json:"public_url"`
	PolicyFile string `json:"policy_file"`

	AgentListen   string `json:"agent_listen"`
	AgentTLSCert  string `json:"agent_tls_cert"`
	AgentTLSKey   string `json:"agent_tls_key"`
	AgentClientCA string `json:"agent_client_ca"`

	OIDC         *OIDC    `json:"oidc"`
	DevLogin     bool     `json:"dev_login"`
	SecureCookie *bool    `json:"secure_cookie"`
	WebSession   Duration `json:"web_session_ttl"`

	CA       CA       `json:"ca"`
	Sessions Sessions `json:"sessions"`
	Smux     Smux     `json:"smux"`

	TicketTTL        Duration `json:"tunnel_ticket_ttl"`
	HeartbeatTimeout Duration `json:"heartbeat_timeout"`
	StreamOpen       Duration `json:"stream_open_timeout"`
	MaxStreams       int      `json:"max_streams_per_agent"`
}

// Agent is the agent configuration.
type Agent struct {
	ServerURL    string            `json:"server_url"` // wss://server:8443
	ServerCA     string            `json:"server_ca"`
	ServerName   string            `json:"server_name"`
	ClientCert   string            `json:"client_cert"`
	ClientKey    string            `json:"client_key"`
	SSHTarget    string            `json:"ssh_target"`
	Labels       map[string]string `json:"reported_labels"`
	MaxStreams   int               `json:"max_concurrent_streams"`
	Heartbeat    Duration          `json:"heartbeat_interval"`
	StreamOpen   Duration          `json:"stream_open_timeout"`
	TCPDial      Duration          `json:"tcp_dial_timeout"`
	RelayDrain   Duration          `json:"relay_drain_timeout"`
	ReconnectMax Duration          `json:"reconnect_max_backoff"`
	Smux         Smux              `json:"smux"`
}

func decode(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// LoadServer reads and validates a server config.
func LoadServer(path string) (*Server, error) {
	var c Server
	if err := decode(path, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.AgentListen == "" {
		c.AgentListen = ":8443"
	}
	if c.PolicyFile == "" || c.PublicURL == "" {
		return nil, errors.New("config: policy_file and public_url are required")
	}
	if c.AgentTLSCert == "" || c.AgentTLSKey == "" || c.AgentClientCA == "" {
		return nil, errors.New("config: agent_tls_cert, agent_tls_key and agent_client_ca are required (Agent mTLS)")
	}
	if c.OIDC == nil && !c.DevLogin {
		return nil, errors.New("config: oidc is required (dev_login is for local development only)")
	}
	return &c, nil
}

// LoadAgent reads and validates an agent config.
func LoadAgent(path string) (*Agent, error) {
	var c Agent
	if err := decode(path, &c); err != nil {
		return nil, err
	}
	if c.ServerURL == "" || c.ClientCert == "" || c.ClientKey == "" {
		return nil, errors.New("config: server_url, client_cert and client_key are required")
	}
	if c.SSHTarget == "" {
		c.SSHTarget = "127.0.0.1:22"
	}
	if err := tunnel.ValidateTarget(c.SSHTarget); err != nil {
		return nil, fmt.Errorf("config: ssh_target: %w", err)
	}
	if c.Labels == nil {
		c.Labels = map[string]string{}
	}
	return &c, nil
}
