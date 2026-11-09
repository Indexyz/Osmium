package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Native SSH tunnel (CLI ↔ Server). The CLI's own OpenSSH client speaks SSH
// end to end with the target sshd; the Server only relays bytes.
//
// Before relaying, the Server sends text messages (same envelope as the
// terminal protocol): any number of native.state, then exactly one of
// native.ready (switch to binary SSH bytes) or native.exit. After the relay
// ends the Server may send a final native.exit. The CLI sends binary frames
// only, and only after native.ready.
const (
	SubprotocolNative = "osmium-native-ssh.v1"

	TypeNativeState = "native.state"
	TypeNativeReady = "native.ready"
	TypeNativeExit  = "native.exit"
)

// NativeReady carries the signed certificate for the CLI's ephemeral key and
// the pinned host keys the CLI must use for strict host key checking.
type NativeReady struct {
	Certificate string    `json:"certificate"` // authorized_keys format
	HostKeys    []string  `json:"host_keys"`   // authorized_keys format
	ValidBefore time.Time `json:"valid_before"`
}

// NativeMessage is a decoded Server → CLI text message.
type NativeMessage struct {
	Type  string
	State *TermState
	Ready *NativeReady
	Exit  *TermExit
}

// DecodeNative parses a Server → CLI text message.
func DecodeNative(b []byte) (*NativeMessage, error) {
	if len(b) > 64*1024 {
		return nil, errors.New("native message too large")
	}
	var env termEnvelope
	if err := json.Unmarshal(b, &env); err != nil || env.Version != 1 {
		return nil, errors.New("invalid native envelope")
	}
	m := &NativeMessage{Type: env.Type}
	var err error
	switch env.Type {
	case TypeNativeState:
		m.State = &TermState{}
		err = json.Unmarshal(env.Payload, m.State)
	case TypeNativeReady:
		m.Ready = &NativeReady{}
		err = json.Unmarshal(env.Payload, m.Ready)
		if err == nil && (m.Ready.Certificate == "" || len(m.Ready.HostKeys) == 0) {
			err = errors.New("native.ready without certificate or host keys")
		}
	case TypeNativeExit:
		m.Exit = &TermExit{}
		err = json.Unmarshal(env.Payload, m.Exit)
	default:
		return nil, fmt.Errorf("unsupported native message %q", env.Type)
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}
