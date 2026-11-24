package protocol

import (
	"testing"
)

func TestControlRoundTrip(t *testing.T) {
	w := Welcome{
		AgentID: "agent-123", HostID: "host-123", Epoch: 7, TunnelID: "t-7",
		SmuxVersion: 2, PingIntervalMs: 45000, PingTimeoutMs: 135000,
	}
	b, err := Encode(TypeWelcome, w)
	if err != nil {
		t.Fatal(err)
	}
	typ, p, err := Decode(b)
	if err != nil || typ != TypeWelcome || p.(*Welcome).HostID != "host-123" || p.(*Welcome).TunnelID != "t-7" {
		t.Fatalf("%s %v %v", typ, p, err)
	}

	mo := MuxOpen{
		Epoch:  7,
		MuxGen: 1,
		Smux: SmuxParams{
			MaxFrameSize:        16 * 1024,
			MaxReceiveBuffer:    4 * 1024 * 1024,
			MaxStreamBuffer:     256 * 1024,
			KeepAliveIntervalMs: 30000,
			KeepAliveTimeoutMs:  90000,
		},
	}
	b, err = Encode(TypeMuxOpen, mo)
	if err != nil {
		t.Fatal(err)
	}
	typ, p, err = Decode(b)
	if err != nil || typ != TypeMuxOpen || p.(*MuxOpen).MuxGen != 1 {
		t.Fatalf("%s %v %v", typ, p, err)
	}

	mc := MuxClose{Epoch: 7, MuxGen: 1, Reason: "idle"}
	b, err = Encode(TypeMuxClose, mc)
	if err != nil {
		t.Fatal(err)
	}
	typ, p, err = Decode(b)
	if err != nil || typ != TypeMuxClose || p.(*MuxClose).Reason != "idle" {
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
		`{"version":1,"type":"agent.welcome","message_id":"m1","payload":{"agent_id":"a","host_id":"h","connection_epoch":1,"tunnel_id":"t1","smux_version":1,"ping_interval_ms":1000,"ping_timeout_ms":3000}}`,
		`{"version":1,"type":"agent.welcome","message_id":"m1","payload":{"agent_id":"a","host_id":"h","connection_epoch":1,"tunnel_id":"t1","smux_version":2,"ping_interval_ms":1000,"ping_timeout_ms":1000}}`,
		`{"version":1,"type":"mux.open","message_id":"m1","payload":{"connection_epoch":1,"mux_gen":0,"smux":{"max_frame_size":16384,"max_receive_buffer":1048576,"max_stream_buffer":262144,"keepalive_interval_ms":10000,"keepalive_timeout_ms":30000}}}`,
		`{"version":1,"type":"mux.open","message_id":"m1","payload":{"connection_epoch":1,"mux_gen":1,"smux":{"max_frame_size":65536,"max_receive_buffer":1048576,"max_stream_buffer":262144,"keepalive_interval_ms":10000,"keepalive_timeout_ms":30000}}}`,
		`{"version":1,"type":"mux.close","message_id":"m1","payload":{"connection_epoch":1,"mux_gen":0,"reason":"idle"}}`,
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
