package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
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
	m, err := newLanManager(raw, netip.MustParseAddr("10.77.0.2"), nil, nil, 1280)
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

func TestLANManagerRejectsUplinkGUIDOrIndexBeforeOpeningDriver(t *testing.T) {
	const id = "{11111111-1111-1111-1111-111111111111}"
	raw := json.RawMessage(`[{"name":"PS5","tunnel_ip":"10.77.0.3","interface_id":"` + id + `","interface_index":30}]`)
	for _, v := range []struct {
		ids     []string
		indices []int
	}{{[]string{id}, nil}, {nil, []int{30}}} {
		m, err := newLanManager(raw, netip.MustParseAddr("10.77.0.2"), v.ids, v.indices, 1280)
		if err == nil || m != nil {
			t.Fatal("uplink accepted as device adapter")
		}
	}
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
	// First out of the adapter is the gratuitous ARP announcing the gateway.
	ann, err := peer.Read(time.Second)
	if err != nil || len(ann) < 14+28 || ann[0] != 0xff || ann[12] != 0x08 || ann[13] != 0x06 {
		t.Fatalf("no gateway announce: %x %v", ann, err)
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
	if m, err := newLanManager(nil, netip.MustParseAddr("10.77.0.2"), nil, nil, 0); m != nil || err != nil {
		t.Fatal("empty config must disable LAN")
	}
	for _, bad := range []string{`[{"name":"x","tunnel_ip":"10.77.0.1","interface_name":"e"}]`, `[{"name":"x","bogus":1}]`} {
		if _, err := newLanManager(json.RawMessage(bad), netip.MustParseAddr("10.77.0.2"), nil, nil, 0); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	var none *lanManager
	if none.dispatch(lanPacket([4]byte{1, 2, 3, 4})) {
		t.Fatal("nil manager must be inert")
	}
}

func TestOpenRedundantBuildsRedBoxOnlyWhenConfigured(t *testing.T) {
	opened := []string{}
	open := func(d lan.DeviceConfig) (lan.FrameIO, error) {
		opened = append(opened, d.InterfaceName)
		a, _ := lan.MemoryPair([6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2})
		return a, nil
	}
	plain, err := openRedundant(open)(lan.DeviceConfig{InterfaceName: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, isBox := plain.(*lan.RedBox); isBox {
		t.Fatal("single adapter wrapped in a RedBox")
	}
	for _, mode := range []string{"prp", "hsr"} {
		opened = nil
		io, err := openRedundant(open)(lan.DeviceConfig{InterfaceName: "eth0", Redundancy: mode, RedundantInterfaceName: "eth1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, isBox := io.(*lan.RedBox); !isBox || len(opened) != 2 || opened[1] != "eth1" {
			t.Fatalf("%s: %T opened %v", mode, io, opened)
		}
		io.Close()
	}
}

func TestUnknownDeviceAskAcceptBlockAndAuto(t *testing.T) {
	dir := t.TempDir()
	m := &lanManager{devices: []lan.DeviceConfig{{Name: "PS5", TunnelIP: netip.MustParseAddr("10.77.0.3"), InterfaceID: "{X}"}},
		client: netip.MustParseAddr("10.77.0.2"), gws: map[string]*runningGateway{}, byIP: map[[4]byte]*lan.Gateway{}, errs: map[string]string{}, retryAt: map[string]time.Time{}}
	m.useAccess(dir)
	mac := [6]byte{2, 0, 0, 0, 0, 9}
	m.noteUnknown(mac, nil)
	m.processAccess()
	st := m.accessStatus().(map[string]any)
	if p := st["pending"].([]lan.Pending); len(p) != 1 || p[0].MAC != "02:00:00:00:00:09" {
		t.Fatalf("closed mode should still list the attempt: %+v", st)
	}
	path := filepath.Join(dir, "lan-access.json")
	lan.UpdateAccess(path, func(a *lan.Access) error {
		a.Accept(lan.AccessEntry{MAC: "02:00:00:00:00:09", Name: "Guest", IP: "10.77.0.10"})
		return nil
	})
	m.access.mtime = time.Time{}
	m.processAccess()
	if all := m.all(); len(all) != 2 || all[1].Name != "Guest" || all[1].DeviceMAC != "02:00:00:00:00:09" || all[1].InterfaceID != "{X}" {
		t.Fatalf("accepted device not added: %+v", all)
	}
	if len(m.accessStatus().(map[string]any)["pending"].([]lan.Pending)) != 0 {
		t.Fatal("decided device still pending")
	}
	lan.UpdateAccess(path, func(a *lan.Access) error { a.Block(lan.AccessEntry{MAC: "02:00:00:00:00:09", Name: "Guest"}); return nil })
	m.access.mtime = time.Time{}
	m.processAccess()
	if len(m.all()) != 1 {
		t.Fatal("blocked device still served")
	}
	m.noteUnknown(mac, nil)
	m.processAccess()
	if m.access.blockedAttempts != 1 {
		t.Fatal("blocked attempt not counted")
	}
	lan.UpdateAccess(path, func(a *lan.Access) error { a.Mode = lan.AccessAuto; return nil })
	m.access.mtime = time.Time{}
	m.noteUnknown([6]byte{2, 0, 0, 0, 0, 7}, nil)
	m.processAccess()
	m.processAccess()
	if all := m.all(); len(all) != 2 || all[1].TunnelIP.String() != "10.77.0.10" {
		t.Fatalf("auto mode did not accept: %+v", all)
	}
}
