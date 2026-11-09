// Package tunnel implements the shared WebSocket + smux data tunnel: the
// per-stream open/ack prelude, the Gateway and Agent stream handshakes and the
// half-close aware relay. Authentication of the underlying WebSocket (mTLS and
// the one-time data ticket) is done by the caller before any function here runs.
package tunnel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// MaxPrelude bounds the JSON prelude exchanged once at the start of a stream.
const MaxPrelude = 16 * 1024

// Stable open_result codes (docs/05 §5).
const (
	CodeOpenDenied       = "OPEN_DENIED"
	CodeInvalidOpen      = "INVALID_OPEN"
	CodeStaleEpoch       = "STALE_EPOCH"
	CodeHostMismatch     = "HOST_MISMATCH"
	CodeDuplicateAttempt = "DUPLICATE_ATTEMPT"
	CodeTooManyStreams   = "TOO_MANY_STREAMS"
	CodeSSHDialFailed    = "SSH_DIAL_FAILED"
	CodeCancelled        = "CANCELLED"
)

var validID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidID reports whether s is a safe opaque identifier.
func ValidID(s string) bool { return validID.MatchString(s) }

// Binding is obtained from authenticated registration, never from the stream.
type Binding struct {
	HostID string
	Epoch  uint64
}

// OpenRequest is the Gateway → Agent prelude. It deliberately has no address or
// port field: the Agent only ever dials its locally configured sshd.
type OpenRequest struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	HostID    string `json:"host_id"`
	SessionID string `json:"session_id"`
	AttemptID string `json:"attempt_id"`
	Epoch     uint64 `json:"connection_epoch"`
}

// CodedError carries a stable open_result code.
type CodedError struct {
	Code string
	Msg  string
}

func (e *CodedError) Error() string { return e.Code + ": " + e.Msg }

// ErrorCode extracts the stable code from err, or "" if none.
func ErrorCode(err error) string {
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

func coded(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// Validate checks the request shape and that it targets the authenticated
// tunnel binding.
func (r OpenRequest) Validate(b Binding) error {
	if r.Version != 1 || r.Type != "ssh.open" || r.Epoch == 0 {
		return coded(CodeInvalidOpen, "invalid open version, type or epoch")
	}
	for _, id := range []string{r.HostID, r.SessionID, r.AttemptID} {
		if !validID.MatchString(id) {
			return coded(CodeInvalidOpen, "invalid identifier")
		}
	}
	if r.HostID != b.HostID {
		return coded(CodeHostMismatch, "stream host does not match tunnel binding")
	}
	if r.Epoch != b.Epoch {
		return coded(CodeStaleEpoch, "stream epoch does not match tunnel binding")
	}
	return nil
}

// OpenResult is the Agent → Gateway ack.
type OpenResult struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	AttemptID string `json:"attempt_id"`
	OK        bool   `json:"ok"`
	Code      string `json:"code,omitempty"`
}

var validCode = regexp.MustCompile(`^[A-Z_]{1,64}$`)

// Validate checks that the ack correlates with q and is self-consistent.
func (r OpenResult) Validate(q OpenRequest) error {
	if r.Version != 1 || r.Type != "ssh.open_result" || r.SessionID != q.SessionID || r.AttemptID != q.AttemptID {
		return errors.New("mismatched open result")
	}
	if r.OK && r.Code != "" || !r.OK && !validCode.MatchString(r.Code) {
		return errors.New("inconsistent open result")
	}
	return nil
}

// WritePrelude writes one uint32-BE length prefixed JSON frame.
func WritePrelude(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) == 0 || len(b) > MaxPrelude {
		return errors.New("invalid prelude length")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, b)
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return errors.New("invalid writer count")
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ReadPrelude reads exactly one frame. JSON decoding never touches the bytes
// that follow (for example the sshd banner).
func ReadPrelude(r io.Reader, dst any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxPrelude {
		return coded(CodeInvalidOpen, "invalid prelude length")
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return coded(CodeInvalidOpen, fmt.Sprintf("invalid prelude JSON: %v", err))
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return coded(CodeInvalidOpen, "trailing prelude JSON")
	}
	return nil
}
