package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"gamebond.local/nativeedge/lan"
)

func lanPacket(dst [4]byte) []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, 17
	p[3] = 28
	copy(p[12:16], []byte{8, 8, 8, 8})
	copy(p[16:20], dst[:])
	return p
}

func newTestLAN(t *testing.T) (*lanManager, *time.Time, *[]map[string]any, *int) {
	t.Helper()
	raw := json.RawMessage(`[{"name":"console","tunnel_ip":"10.77.0.9","interface_name":"eth9","device_mac":"02:00:00:00:00:aa"}]`)
	m, err := newLanManager(raw, netip.MustParseAddr("10.77.0.2"), nil, 1280)
	if err != nil || m == nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	var lines []map[string]any
	opens := 0
	m.now = func() time.Time { return now }
	m.out = func(l map[string]any) { lines = append(lines, l) }
	m.outbound = func([]byte) bool { return true }
	return m, &now, &lines, &opens
}

func TestLANManagerRetriesAndDelivers(t *testing.T) {
	m, now, lines, opens := newTestLAN(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var peer *lan.MemoryIO
	fail := true
	m.open = func(lan.DeviceConfig) (lan.FrameIO, error) {
		*opens++
		if fail {
			return nil, errors.New("no such adapter")
		}
		var a *lan.MemoryIO
		a, peer = lan.MemoryPair([6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2})
		return a, nil
	}
	m.maintain(ctx)
	m.maintain(ctx) // inside the 5 s retry window: no second open
	if *opens != 1 || len(*lines) != 1 || (*lines)[0]["status"] != "lan_device_unavailable" {
		t.Fatalf("opens=%d lines=%v", *opens, *lines)
	}
	row := m.status().([]map[string]any)[0]
	if row["up"] != false || row["error"] != "no such adapter" {
		t.Fatalf("%v", row)
	}
	fail = false
	*now = now.Add(5 * time.Second)
	m.maintain(ctx)
	if *opens != 2 || (*lines)[len(*lines)-1]["status"] != "lan_device_up" {
		t.Fatalf("opens=%d lines=%v", *opens, *lines)
	}
	// A packet for the device leaves its adapter; others are not ours.
	if !m.dispatch(lanPacket([4]byte{10, 77, 0, 9})) {
		t.Fatal("device packet not claimed")
	}
	if m.dispatch(lanPacket([4]byte{10, 77, 0, 2})) {
		t.Fatal("client packet claimed by a gateway")
	}
	f, err := peer.Read(time.Second)
	if err != nil || len(f) < 14+28 || f[0] != 2 || f[5] != 0xaa {
		t.Fatalf("frame %x %v", f, err)
	}
	// Adapter failure: the gateway is replaced on the next maintain after retry.
	m.mu.Lock()
	first := m.gws["console"]
	m.mu.Unlock()
	first.io.Close()
	deadline := time.Now().Add(3 * time.Second)
	for first.alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if first.alive() {
		t.Fatal("gateway did not stop when its adapter closed")
	}
	*now = now.Add(6 * time.Second)
	m.maintain(ctx)
	m.mu.Lock()
	second := m.gws["console"]
	m.mu.Unlock()
	if second == nil || second == first || *opens != 3 {
		t.Fatalf("not restarted: opens=%d", *opens)
	}
	found := false
	for _, l := range *lines {
		found = found || l["status"] == "lan_device_down"
	}
	if !found {
		t.Fatalf("no lan_device_down line: %v", *lines)
	}
}

func TestLANManagerConfig(t *testing.T) {
	if m, err := newLanManager(nil, netip.MustParseAddr("10.77.0.2"), nil, 0); m != nil || err != nil {
		t.Fatal("empty config must disable LAN")
	}
	for _, bad := range []string{`[{"name":"x","tunnel_ip":"10.77.0.1","interface_name":"e"}]`, `[{"name":"x","bogus":1}]`} {
		if _, err := newLanManager(json.RawMessage(bad), netip.MustParseAddr("10.77.0.2"), nil, 0); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	var none *lanManager
	if none.dispatch(lanPacket([4]byte{1, 2, 3, 4})) || none.dnsStatus() != nil {
		t.Fatal("nil manager must be inert")
	}
}
