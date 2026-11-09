package stackio

import (
	"bytes"
	"io"
	"testing"
	"time"
)

type fakeUplink struct{ got [][]byte }

func (f *fakeUplink) Send(p []byte, _ string, _ time.Duration) bool {
	f.got = append(f.got, append([]byte(nil), p...))
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
