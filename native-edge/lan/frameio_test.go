package lan

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// A device on a MemoryIO pair gets a DHCP offer and ACK from the running gateway.
func TestRunServesDHCPOverMemoryIO(t *testing.T) {
	gwIO, devIO := MemoryPair([6]byte{2, 0, 0, 0, 0, 1}, [6]byte{0xa, 0, 0, 0, 0, 1})
	g, err := NewGateway(Config{Device: Device{Name: "c", TunnelIP: netip.MustParseAddr("10.77.0.9")}, ClientIP: netip.MustParseAddr("10.77.0.2"), OnPacket: func([]byte) {}}, gwIO)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx, gwIO) }()
	mac := devIO.MAC()
	body := make([]byte, 240)
	body[0], body[1], body[2] = 1, 1, 6
	copy(body[28:], mac[:])
	copy(body[236:], []byte{0x63, 0x82, 0x53, 0x63})
	body = append(body, 53, 1, 1, 255)
	bc := [4]byte{255, 255, 255, 255}
	pkt := buildIPv4([4]byte{}, bc, 17, buildUDP([4]byte{}, bc, 68, 67, body), 1)
	frame := append(append(append([]byte{}, broadcastMAC[:]...), mac[:]...), 0x08, 0x00)
	if err := devIO.Write(append(frame, pkt...)); err != nil {
		t.Fatal(err)
	}
	f, err := devIO.Read(2 * time.Second)
	if err != nil || len(f) < 60 {
		t.Fatalf("no offer: %v %x", err, f)
	}
	if g.Stats().DHCPOffers != 1 {
		t.Fatalf("offers = %d", g.Stats().DHCPOffers)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	gwIO.Close()
	if _, err := gwIO.Read(time.Millisecond); err == nil {
		t.Fatal("read after close succeeded")
	}
}
