package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func request() OpenRequest {
	return OpenRequest{Version: 1, Type: "ssh.open", HostID: "host-123", SessionID: "s789", AttemptID: "a001", Epoch: 7}
}

func TestPreludeDoesNotConsumeSSHBanner(t *testing.T) {
	var b bytes.Buffer
	q := request()
	if err := WritePrelude(&b, q); err != nil {
		t.Fatal(err)
	}
	banner := "SSH-2.0-test\r\n"
	b.WriteString(banner)
	var got OpenRequest
	if err := ReadPrelude(&b, &got); err != nil {
		t.Fatal(err)
	}
	if got != q || b.String() != banner {
		t.Fatalf("bad frame or consumed banner: %#v %q", got, b.String())
	}
}

func TestPreludeLengthBounds(t *testing.T) {
	for _, n := range []uint32{0, MaxPrelude + 1, 0xffffffff} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		var q OpenRequest
		if err := ReadPrelude(bytes.NewReader(b[:]), &q); err == nil {
			t.Fatalf("accepted length %d", n)
		}
	}
}

func rawFrame(s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b[:4], uint32(len(s)))
	copy(b[4:], s)
	return b
}
func TestRejectUnknownAndTrailingFields(t *testing.T) {
	for _, s := range []string{`{"target":"evil:22"}`, `{} {}`, `{"version":`} {
		var q OpenRequest
		if err := ReadPrelude(bytes.NewReader(rawFrame(s)), &q); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestRejectTruncatedFrame(t *testing.T) {
	b := rawFrame(`{}`)
	var q OpenRequest
	if err := ReadPrelude(bytes.NewReader(b[:len(b)-1]), &q); err == nil {
		t.Fatal("accepted truncation")
	}
}
func TestBindingAndIDs(t *testing.T) {
	q := request()
	if err := q.Validate(Binding{"host-123", 7}); err != nil {
		t.Fatal(err)
	}
	for _, b := range []Binding{{"host-456", 7}, {"host-123", 8}} {
		if err := q.Validate(b); err == nil {
			t.Fatal("accepted wrong binding")
		}
	}
	q.SessionID = "../../bad"
	if err := q.Validate(Binding{"host-123", 7}); err == nil {
		t.Fatal("accepted unsafe ID")
	}
}
func TestResultCorrelation(t *testing.T) {
	q := request()
	good := OpenResult{Version: 1, Type: "ssh.open_result", SessionID: q.SessionID, AttemptID: q.AttemptID, OK: true}
	if err := good.Validate(q); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.AttemptID = "wrong"
	if err := bad.Validate(q); err == nil {
		t.Fatal("accepted wrong attempt")
	}
	bad = good
	bad.Code = "ERROR"
	if err := bad.Validate(q); err == nil {
		t.Fatal("accepted success with error code")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 2 {
		b = b[:2]
	}
	return w.Buffer.Write(b)
}
func TestShortWritesHandled(t *testing.T) {
	var w shortWriter
	q := request()
	if err := WritePrelude(&w, q); err != nil {
		t.Fatal(err)
	}
	var got OpenRequest
	if err := ReadPrelude(&w.Buffer, &got); err != nil {
		t.Fatal(err)
	}
	if got != q {
		t.Fatal("short writes corrupted frame")
	}
}

type stalledWriter struct{}

func (stalledWriter) Write([]byte) (int, error) { return 0, nil }
func TestZeroProgressWrite(t *testing.T) {
	if err := writeFull(stalledWriter{}, []byte("x")); err != io.ErrShortWrite {
		t.Fatalf("got %v", err)
	}
}

func TestValidIDAndCode(t *testing.T) {
	long := strings.Repeat("a", 128)
	for s, want := range map[string]bool{
		"host-123": true, "a.b_c-D9": true, long: true,
		"": false, long + "a": false, "a b": false, "a/b": false, "a\n": false, "é": false, "a:b": false,
	} {
		if got := ValidID(s); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", s, got, want)
		}
	}
	for s, want := range map[string]bool{
		"HOST_MISMATCH": true, strings.Repeat("A", 64): true,
		"": false, strings.Repeat("A", 65): false, "lower": false, "A-B": false, "A1": false,
	} {
		if got := validCode(s); got != want {
			t.Errorf("validCode(%q) = %v, want %v", s, got, want)
		}
	}
}
