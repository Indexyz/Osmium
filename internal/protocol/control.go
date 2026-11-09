// Package protocol defines the Agent control channel messages (version 1,
// api/control.schema.json) and the browser terminal text messages
// (api/terminal.schema.json).
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// WebSocket subprotocols.
const (
	SubprotocolControl  = "web-ssh-control.v1"
	SubprotocolData     = "web-ssh-data.v1"
	SubprotocolTerminal = "web-ssh-terminal.v1"

	ControlPath = "/agent/v1/control"
	DataPath    = "/agent/v1/data"

	// MaxControlMessage bounds a single control JSON message.
	MaxControlMessage = 64 * 1024
)

// Control message types.
const (
	TypeHello     = "agent.hello"
	TypeWelcome   = "agent.welcome"
	TypeHeartbeat = "agent.heartbeat"
	TypeDataReady = "agent.data_ready"
	TypeClose     = "session.close"
	TypeClosed    = "session.closed"
)

var validID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Envelope is the common control message wrapper.
type Envelope struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	MessageID string          `json:"message_id"`
	Payload   json.RawMessage `json:"payload"`
}

type Hello struct {
	AgentVersion   string            `json:"agent_version"`
	ReportedLabels map[string]string `json:"reported_labels"`
}

type Welcome struct {
	AgentID      string    `json:"agent_id"`
	HostID       string    `json:"host_id"`
	Epoch        uint64    `json:"connection_epoch"`
	DataTunnelID string    `json:"data_tunnel_id"`
	DataPath     string    `json:"data_path"`
	DataTicket   string    `json:"data_ticket"`
	ExpiresAt    time.Time `json:"expires_at"`
	SmuxVersion  int       `json:"smux_version"`
}

type Heartbeat struct {
	Epoch         uint64 `json:"connection_epoch"`
	DataTunnelID  string `json:"data_tunnel_id"`
	DataConnected bool   `json:"data_connected"`
	ActiveStreams int    `json:"active_streams"`
}

type DataReady struct {
	Epoch        uint64 `json:"connection_epoch"`
	DataTunnelID string `json:"data_tunnel_id"`
}

// SessionClose is used for both session.close and session.closed.
type SessionClose struct {
	Epoch     uint64 `json:"connection_epoch"`
	SessionID string `json:"session_id"`
	AttemptID string `json:"attempt_id"`
	Reason    string `json:"reason"`
}

// NewMessageID returns a random message identifier.
func NewMessageID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "m-" + hex.EncodeToString(b[:])
}

// Encode builds a version 1 control message.
func Encode(typ string, payload any) ([]byte, error) {
	if err := validatePayload(typ, payload); err != nil {
		return nil, err
	}
	p, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Version: 1, Type: typ, MessageID: NewMessageID(), Payload: p})
}

func strictDecode(b []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// Decode parses and validates one control message, returning its type and a
// pointer to the typed payload.
func Decode(b []byte) (string, any, error) {
	if len(b) > MaxControlMessage {
		return "", nil, errors.New("control message too large")
	}
	var env Envelope
	if err := strictDecode(b, &env); err != nil {
		return "", nil, fmt.Errorf("invalid envelope: %w", err)
	}
	if env.Version != 1 || !validID.MatchString(env.MessageID) || len(env.Payload) == 0 {
		return "", nil, errors.New("invalid envelope fields")
	}
	var p any
	switch env.Type {
	case TypeHello:
		p = &Hello{}
	case TypeWelcome:
		p = &Welcome{}
	case TypeHeartbeat:
		p = &Heartbeat{}
	case TypeDataReady:
		p = &DataReady{}
	case TypeClose, TypeClosed:
		p = &SessionClose{}
	default:
		return "", nil, fmt.Errorf("unknown control type %q", env.Type)
	}
	if err := strictDecode(env.Payload, p); err != nil {
		return "", nil, fmt.Errorf("invalid %s payload: %w", env.Type, err)
	}
	if err := validatePayload(env.Type, p); err != nil {
		return "", nil, err
	}
	return env.Type, p, nil
}

func deref(p any) any {
	switch v := p.(type) {
	case *Hello:
		return *v
	case *Welcome:
		return *v
	case *Heartbeat:
		return *v
	case *DataReady:
		return *v
	case *SessionClose:
		return *v
	}
	return p
}

func validatePayload(typ string, p any) error {
	bad := func(what string) error { return fmt.Errorf("invalid %s: %s", typ, what) }
	switch v := deref(p).(type) {
	case Hello:
		if typ != TypeHello || len(v.AgentVersion) > 64 || v.ReportedLabels == nil || len(v.ReportedLabels) > 64 {
			return bad("fields")
		}
		for _, val := range v.ReportedLabels {
			if len(val) > 256 {
				return bad("label value too long")
			}
		}
	case Welcome:
		if typ != TypeWelcome || !validID.MatchString(v.AgentID) || !validID.MatchString(v.HostID) || v.Epoch == 0 ||
			!validID.MatchString(v.DataTunnelID) || v.DataPath != DataPath || len(v.DataTicket) < 16 || len(v.DataTicket) > 2048 ||
			v.ExpiresAt.IsZero() || v.SmuxVersion != 2 {
			return bad("fields")
		}
	case Heartbeat:
		if typ != TypeHeartbeat || v.Epoch == 0 || !validID.MatchString(v.DataTunnelID) || v.ActiveStreams < 0 {
			return bad("fields")
		}
	case DataReady:
		if typ != TypeDataReady || v.Epoch == 0 || !validID.MatchString(v.DataTunnelID) {
			return bad("fields")
		}
	case SessionClose:
		if (typ != TypeClose && typ != TypeClosed) || v.Epoch == 0 || !validID.MatchString(v.SessionID) ||
			!validID.MatchString(v.AttemptID) || len(v.Reason) > 256 {
			return bad("fields")
		}
	default:
		return bad("unknown payload")
	}
	return nil
}
