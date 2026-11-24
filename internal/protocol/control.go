// Package protocol defines the Agent single-WSS control messages (version 1)
// and the browser terminal text messages.
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/indexyz/osmium/internal/tunnel"
)

// WebSocket subprotocols and paths.
const (
	// SubprotocolTunnel is the unified single-WSS Agent protocol:
	//   - WebSocket Ping/Pong: keepalive
	//   - WebSocket Text:      JSON control messages (version 1)
	//   - WebSocket Binary:    [4B big-endian mux_gen][smux v2 bytes]
	SubprotocolTunnel   = "web-ssh-tunnel.v2"
	SubprotocolTerminal = "web-ssh-terminal.v1"

	TunnelPath = "/agent/v1/tunnel"

	// MaxControlMessage bounds a single JSON control text frame.
	MaxControlMessage = 64 * 1024
	// MaxBinaryMessage bounds a single binary WebSocket frame carrying
	// [4B mux_gen][smux v2 frame]. smux MaxFrameSize is capped at 32 KiB + 8B header.
	MaxBinaryMessage = 128 * 1024
)

// Control message types (carried in WebSocket text frames).
const (
	TypeHello    = "agent.hello"
	TypeWelcome  = "agent.welcome"
	TypeMuxOpen  = "mux.open"
	TypeMuxClose = "mux.close"
	TypeClose    = "session.close"
	TypeClosed   = "session.closed"
)

// validID is shared with the stream prelude so both channels accept the same IDs.
var validID = tunnel.ValidID

// Envelope is the common control message wrapper.
type Envelope struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	MessageID string          `json:"message_id"`
	Payload   json.RawMessage `json:"payload"`
}

// Hello is sent by the Agent as the first text frame after mTLS WSS upgrade.
type Hello struct {
	AgentVersion   string            `json:"agent_version"`
	ReportedLabels map[string]string `json:"reported_labels"`
}

// Welcome binds the Agent connection to its server-assigned identity and epoch.
type Welcome struct {
	AgentID        string `json:"agent_id"`
	HostID         string `json:"host_id"`
	Epoch          uint64 `json:"connection_epoch"`
	TunnelID       string `json:"tunnel_id"`
	SmuxVersion    int    `json:"smux_version"`
	PingIntervalMs int    `json:"ping_interval_ms"`
	PingTimeoutMs  int    `json:"ping_timeout_ms"`
}

// SmuxParams carries bounded, server-dictated smux v2 parameters for an
// on-demand mux generation.
type SmuxParams struct {
	MaxFrameSize        int `json:"max_frame_size"`
	MaxReceiveBuffer    int `json:"max_receive_buffer"`
	MaxStreamBuffer     int `json:"max_stream_buffer"`
	KeepAliveIntervalMs int `json:"keepalive_interval_ms"`
	KeepAliveTimeoutMs  int `json:"keepalive_timeout_ms"`
}

// Validate checks that SmuxParams stay within safe memory and liveness bounds.
func (s SmuxParams) Validate() error {
	if s.MaxFrameSize < 1024 || s.MaxFrameSize > 32*1024 {
		return errors.New("max_frame_size out of bounds")
	}
	if s.MaxReceiveBuffer < 64*1024 || s.MaxReceiveBuffer > 16*1024*1024 {
		return errors.New("max_receive_buffer out of bounds")
	}
	if s.MaxStreamBuffer < 16*1024 || s.MaxStreamBuffer > 4*1024*1024 || s.MaxStreamBuffer > s.MaxReceiveBuffer {
		return errors.New("max_stream_buffer out of bounds")
	}
	if s.KeepAliveIntervalMs < 1000 || s.KeepAliveIntervalMs > 300_000 {
		return errors.New("keepalive_interval_ms out of bounds")
	}
	if s.KeepAliveTimeoutMs < s.KeepAliveIntervalMs*2 || s.KeepAliveTimeoutMs > 600_000 {
		return errors.New("keepalive_timeout_ms out of bounds")
	}
	return nil
}

// MuxOpen activates an on-demand smux v2 session bound to MuxGen on the shared WSS.
type MuxOpen struct {
	Epoch  uint64     `json:"connection_epoch"`
	MuxGen uint32     `json:"mux_gen"`
	Smux   SmuxParams `json:"smux"`
}

// MuxClose retires an idle or superseded smux v2 session without closing the WSS.
type MuxClose struct {
	Epoch  uint64 `json:"connection_epoch"`
	MuxGen uint32 `json:"mux_gen"`
	Reason string `json:"reason"`
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
	if env.Version != 1 || !validID(env.MessageID) || len(env.Payload) == 0 {
		return "", nil, errors.New("invalid envelope fields")
	}
	var p any
	switch env.Type {
	case TypeHello:
		p = &Hello{}
	case TypeWelcome:
		p = &Welcome{}
	case TypeMuxOpen:
		p = &MuxOpen{}
	case TypeMuxClose:
		p = &MuxClose{}
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
	case *MuxOpen:
		return *v
	case *MuxClose:
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
		if typ != TypeWelcome || !validID(v.AgentID) || !validID(v.HostID) || v.Epoch == 0 ||
			!validID(v.TunnelID) || v.SmuxVersion != 2 ||
			v.PingIntervalMs < 200 || v.PingIntervalMs > 600_000 ||
			v.PingTimeoutMs < v.PingIntervalMs*2 || v.PingTimeoutMs > 1_800_000 {
			return bad("fields")
		}
	case MuxOpen:
		if typ != TypeMuxOpen || v.Epoch == 0 || v.MuxGen == 0 {
			return bad("fields")
		}
		if err := v.Smux.Validate(); err != nil {
			return bad(err.Error())
		}
	case MuxClose:
		if typ != TypeMuxClose || v.Epoch == 0 || v.MuxGen == 0 || len(v.Reason) > 256 {
			return bad("fields")
		}
	case SessionClose:
		if (typ != TypeClose && typ != TypeClosed) || v.Epoch == 0 || !validID(v.SessionID) ||
			!validID(v.AttemptID) || len(v.Reason) > 256 {
			return bad("fields")
		}
	default:
		return bad("unknown payload")
	}
	return nil
}
