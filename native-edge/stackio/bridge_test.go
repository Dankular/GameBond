package stackio

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"github.com/Dankular/GameBond.Core/bond"
	"io"
	"testing"
)

type fakeUplink struct {
	got    [][]byte
	queued []bond.QueuedPacket
}

func (f *fakeUplink) Submit(q bond.QueuedPacket) bool {
	f.got = append(f.got, append([]byte(nil), q.Payload...))
	f.queued = append(f.queued, q)
	return true
}

func TestBridgeMovesPacketsAndEventsBothWays(t *testing.T) {
	var toStack bytes.Buffer
	up := &fakeUplink{}
	var events []map[string]any
	b := &Bridge{Out: NewWriter(&toStack), Uplink: up, OnEvent: func(m map[string]any) { events = append(events, m) }}

	var fromStack bytes.Buffer
	w := NewWriter(&fromStack)
	w.Write(KindPacket, []byte("packet-one"))
	w.Write(KindStackEvent, []byte(`{"socks":"127.0.0.1:1080"}`))
	w.Write(KindStackEvent, []byte(`not json`))
	if err := b.Pump(&fromStack); err != io.EOF {
		t.Fatalf("pump ended with %v", err)
	}
	if len(up.got) != 1 || string(up.got[0]) != "packet-one" || b.Outbound.Load() != 1 {
		t.Fatalf("outbound %q", up.got)
	}
	if len(events) != 1 || events[0]["socks"] != "127.0.0.1:1080" || b.Malformed.Load() != 1 {
		t.Fatalf("events %v malformed %d", events, b.Malformed.Load())
	}

	b.Deliver([]byte("reply"))
	b.Deliver(make([]byte, 1281)) // too large for the stack
	if err := b.Respond(map[string]any{"type": "app_authorization_response", "allow": false}); err != nil {
		t.Fatal(err)
	}
	f1, _ := Read(&toStack)
	f2, _ := Read(&toStack)
	if f1.Kind != KindPacket || string(f1.Payload) != "reply" || f2.Kind != KindStackAnswer || b.Injected.Load() != 1 || b.Malformed.Load() != 2 {
		t.Fatalf("inbound frames %+v %+v", f1, f2)
	}
	// An unexpected kind from the stack ends the bridge.
	var bad bytes.Buffer
	NewWriter(&bad).Write(1, []byte("x"))
	if b.Pump(&bad) != ErrFrame {
		t.Fatal("unexpected endpoint accepted")
	}
}

func udpPacket(sport, dport uint16) []byte {
	p := make([]byte, 28+20)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:], []byte{10, 0, 0, 1})
	copy(p[16:], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], 28)
	return p
}

func TestBridgeMarksAndClassifiesGameUDP(t *testing.T) {
	settings := bond.DefaultQoSSettings()
	classifier, err := bond.NewClassifier(nil, []uint16{27015}, settings)
	if err != nil {
		t.Fatal(err)
	}
	up := &fakeUplink{}
	b := &Bridge{Out: NewWriter(io.Discard), Uplink: up, Classifier: classifier, GamePorts: map[uint16]bool{27015: true}}
	var in bytes.Buffer
	w := NewWriter(&in)
	w.Write(KindPacket, udpPacket(50000, 27015))
	w.Write(KindPacket, udpPacket(50000, 443))
	w.Write(KindPacket, []byte("garbage"))
	b.Pump(&in)
	if len(up.queued) != 3 {
		t.Fatalf("queued %d", len(up.queued))
	}
	game, bulk, junk := up.queued[0], up.queued[1], up.queued[2]
	if !game.Priority || !game.Replicate || game.Tag != 46 || game.Payload[1]>>2 != 46 {
		t.Fatalf("game packet not prioritised/marked: %+v", game)
	}
	if bulk.Priority || bulk.Tag != 0 {
		t.Fatalf("ordinary UDP promoted: %+v", bulk)
	}
	if junk.Priority || string(junk.Payload) != "garbage" {
		t.Fatalf("unparseable packet must pass through as bulk: %+v", junk)
	}
}

func TestEventNumbersKeepPythonIntFloatDistinction(t *testing.T) {
	var got map[string]any
	b := &Bridge{Out: NewWriter(&bytes.Buffer{}), Uplink: &fakeUplink{}, OnEvent: func(m map[string]any) { got = m }}
	var from bytes.Buffer
	w := NewWriter(&from)
	w.Write(KindStackEvent, []byte(`{"pid":7,"rate":1.5,"big":18446744073709551615}`))
	w.Write(KindStackEvent, []byte(`{"a":1} trailing`))
	b.Pump(&from)
	if got["pid"] != json.Number("7") || got["rate"] != json.Number("1.5") || got["big"] != json.Number("18446744073709551615") {
		t.Fatalf("%#v", got)
	}
	if b.Malformed.Load() != 1 {
		t.Fatalf("trailing garbage must count as malformed, got %d", b.Malformed.Load())
	}
}

func TestAppFlowProfileRecordsReclassifyThatFlow(t *testing.T) {
	classifier, _ := bond.NewClassifier(nil, nil, bond.DefaultQoSSettings())
	up := &fakeUplink{}
	var unhandled int
	b := &Bridge{Out: NewWriter(io.Discard), Uplink: up, Classifier: classifier, GamePorts: map[uint16]bool{}, Profiles: &bond.FlowProfiles{}, ClientIP: "10.0.0.1",
		OnEvent: func(map[string]any) { unhandled++ }}
	var in bytes.Buffer
	w := NewWriter(&in)
	w.Write(KindPacket, udpPacket(50000, 443)) // before the record: bulk
	w.Write(KindStackEvent, []byte(`{"type":"app_flow_profile","profile":"call","protocol":"udp","source":"10.0.0.1:50000","destination":"10.0.0.2:443"}`))
	w.Write(KindPacket, udpPacket(50000, 443))
	w.Write(KindPacket, udpPacket(50001, 443)) // another flow: untouched
	w.Write(KindStackEvent, []byte(`{"type":"other"}`))
	b.Pump(&in)
	if len(up.queued) != 3 || unhandled != 1 {
		t.Fatalf("queued %d, unhandled %d", len(up.queued), unhandled)
	}
	if q := up.queued[0]; q.Tag != 0 || q.Priority {
		t.Fatalf("%+v", q)
	}
	if q := up.queued[1]; q.Tag != 26 || !q.Priority || q.Payload[1]>>2 != 26 {
		t.Fatalf("profiled flow not reclassified and marked: %+v", q)
	}
	if q := up.queued[2]; q.Tag != 0 {
		t.Fatalf("other flow affected: %+v", q)
	}
}
