package protocol

import (
	"testing"
	"time"
)

func TestControlRoundTrip(t *testing.T) {
	w := Welcome{AgentID: "agent-123", HostID: "host-123", Epoch: 7, DataTunnelID: "dt-7", DataPath: DataPath, DataTicket: "0123456789abcdef0123", ExpiresAt: time.Now(), SmuxVersion: 2}
	b, err := Encode(TypeWelcome, w)
	if err != nil {
		t.Fatal(err)
	}
	typ, p, err := Decode(b)
	if err != nil || typ != TypeWelcome || p.(*Welcome).HostID != "host-123" {
		t.Fatalf("%s %v %v", typ, p, err)
	}
}

func TestControlRejects(t *testing.T) {
	for _, s := range []string{
		`{"version":1,"type":"agent.hello","message_id":"m1","payload":{"agent_version":"x","reported_labels":{},"evil":1}}`,
		`{"version":2,"type":"agent.hello","message_id":"m1","payload":{"agent_version":"x","reported_labels":{}}}`,
		`{"version":1,"type":"session.open","message_id":"m1","payload":{}}`,
		`{"version":1,"type":"session.close","message_id":"m1","payload":{"connection_epoch":0,"session_id":"s","attempt_id":"a","reason":""}}`,
		`{"version":1,"type":"session.close","message_id":"m1","payload":{"connection_epoch":1,"session_id":"../x","attempt_id":"a","reason":""}}`,
		`{"version":1,"type":"agent.welcome","message_id":"m1","payload":{"agent_id":"a","host_id":"h","connection_epoch":1,"data_tunnel_id":"d","data_path":"https://evil/agent/v1/data","data_ticket":"0123456789abcdef","expires_at":"2026-01-01T00:00:00Z","smux_version":2}}`,
		`{"version":1,"type":"agent.hello","message_id":"m1","payload":{"agent_version":"x","reported_labels":{}}} {}`,
	} {
		if _, _, err := Decode([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}

func TestTerminalDecode(t *testing.T) {
	typ, r, err := DecodeTerminal([]byte(`{"version":1,"type":"terminal.resize","payload":{"rows":40,"cols":120}}`))
	if err != nil || typ != TypeTermResize || r.Rows != 40 {
		t.Fatal(err)
	}
	for _, s := range []string{
		`{"version":1,"type":"terminal.resize","payload":{"rows":0,"cols":120}}`,
		`{"version":1,"type":"terminal.resize","payload":{"rows":10,"cols":1001}}`,
		`{"version":1,"type":"terminal.state","payload":{"state":"active"}}`,
		`{"version":1,"type":"terminal.close","payload":{"x":1}}`,
		`not json`,
	} {
		if _, _, err := DecodeTerminal([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
