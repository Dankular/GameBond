package lan

import (
	"net/netip"
	"testing"
	"time"
)

func TestDevicePowerOffDisconnectsAndReturnReconnects(t *testing.T) {
	now := time.Unix(1000, 0)
	cfg := Config{Device: Device{Name: "PS5", TunnelIP: netip.MustParseAddr("10.77.0.3")}, ClientIP: netip.MustParseAddr("10.77.0.2"),
		TunnelMTU: 1280, Now: func() time.Time { return now }, OnPacket: func([]byte) {}}
	g, err := NewGateway(cfg, &fakeIO{})
	if err != nil {
		t.Fatal(err)
	}
	if g.Present() || g.IsLeased() {
		t.Fatal("device present before any frame")
	}
	dev := [6]byte{0xc8, 0xa3, 0x62, 0x30, 0x4e, 0xb2}
	arp := func() []byte {
		f := make([]byte, 14+28)
		copy(f[0:6], broadcastMAC[:])
		copy(f[6:12], dev[:])
		f[12], f[13] = 0x08, 0x06
		copy(f[14:], []byte{0, 1, 8, 0, 6, 4, 0, 1})
		copy(f[22:28], dev[:])
		copy(f[28:32], g.device[:])
		copy(f[38:42], g.gateway[:])
		return f
	}
	g.HandleFrame(arp())
	g.Leased = true
	if !g.Present() || !g.IsLeased() {
		t.Fatal("device not present after a frame")
	}
	now = now.Add(PresenceTimeout - time.Second)
	if !g.IsLeased() {
		t.Fatal("device dropped before the timeout")
	}
	now = now.Add(2 * time.Second)
	if g.Present() || g.IsLeased() || g.SilentFor() < PresenceTimeout {
		t.Fatal("powered-off device still shown as connected")
	}
	g.HandleFrame(arp())
	if !g.Present() || !g.IsLeased() {
		t.Fatal("device did not reconnect when it returned")
	}
}
