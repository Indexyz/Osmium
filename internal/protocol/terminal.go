package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Terminal text message types.
const (
	TypeTermResize = "terminal.resize"
	TypeTermClose  = "terminal.close"
	TypeTermState  = "terminal.state"
	TypeTermExit   = "terminal.exit"
)

type TermResize struct {
	Rows int `json:"rows"`
	Cols int `json:"cols"`
}

type TermState struct {
	State string `json:"state"`
}

type TermExit struct {
	Reason     string `json:"reason"`
	ExitStatus *int   `json:"exit_status,omitempty"`
}

type termEnvelope struct {
	Version int             `json:"version"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// ValidTermSize checks rows/cols bounds (1..1000).
func ValidTermSize(rows, cols int) bool {
	return rows >= 1 && rows <= 1000 && cols >= 1 && cols <= 1000
}

// DecodeTerminal parses a browser → server text message. It returns either a
// *TermResize or nil for terminal.close.
func DecodeTerminal(b []byte) (string, *TermResize, error) {
	if len(b) > 4096 {
		return "", nil, errors.New("terminal message too large")
	}
	var env termEnvelope
	if err := strictDecode(b, &env); err != nil {
		return "", nil, fmt.Errorf("invalid terminal message: %w", err)
	}
	if env.Version != 1 || len(env.Payload) == 0 {
		return "", nil, errors.New("invalid terminal envelope")
	}
	switch env.Type {
	case TypeTermResize:
		var r TermResize
		if err := strictDecode(env.Payload, &r); err != nil {
			return "", nil, err
		}
		if !ValidTermSize(r.Rows, r.Cols) {
			return "", nil, errors.New("terminal size out of range")
		}
		return env.Type, &r, nil
	case TypeTermClose:
		var empty struct{}
		if err := strictDecode(env.Payload, &empty); err != nil {
			return "", nil, err
		}
		return env.Type, nil, nil
	}
	return "", nil, fmt.Errorf("unsupported terminal message %q", env.Type)
}

// EncodeTerminal builds a server → browser text message.
func EncodeTerminal(typ string, payload any) []byte {
	p, _ := json.Marshal(payload)
	b, _ := json.Marshal(termEnvelope{Version: 1, Type: typ, Payload: p})
	return b
}
