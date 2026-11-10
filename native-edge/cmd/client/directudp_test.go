package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func devicePacket(src [4]byte, sport uint16, dst [4]byte, dport uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

func TestDirectUDPRoundTrip(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	go func() { // echo with a prefix
		b := make([]byte, 2048)
		for {
			n, from, err := remote.ReadFromUDP(b)
			if err != nil {
				return
			}
			remote.WriteToUDP(append([]byte("re:"), b[:n]...), from)
		}
	}()
	got := make(chan []byte, 4)
	d := newDirectUDP(func() (*net.UDPConn, error) { return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}) },
		func(p []byte) bool { got <- append([]byte(nil), p...); return true })
	d.allow = func(netip.Addr) bool { return true }
	defer d.close()
	rp := remote.LocalAddr().(*net.UDPAddr)
	dev := [4]byte{10, 77, 0, 3}
	if !d.Handle(devicePacket(dev, 40000, [4]byte{127, 0, 0, 1}, uint16(rp.Port), []byte("hit"))) {
		t.Fatal("eligible packet not sent direct")
	}
	select {
	case p := <-got:
		if string(p[28:]) != "re:hit" || [4]byte(p[16:20]) != dev || binary.BigEndian.Uint16(p[22:]) != 40000 || binary.BigEndian.Uint16(p[20:]) != uint16(rp.Port) {
			t.Fatalf("bad reply %x", p)
		}
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[i:]))
		}
		for sum > 0xffff {
			sum = sum&0xffff + sum>>16
		}
		if uint16(sum) != 0xffff {
			t.Fatal("bad IPv4 header checksum")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reply delivered to the device")
	}
	if d.stats()["flows_active"].(int) != 1 {
		t.Fatal("flow not tracked")
	}
}

func TestDirectUDPLeavesOtherTrafficToTheTunnel(t *testing.T) {
	d := newDirectUDP(func() (*net.UDPConn, error) { t.Fatal("must not open a socket"); return nil, nil }, func([]byte) bool { return true })
	dev := [4]byte{10, 77, 0, 3}
	pub := [4]byte{93, 184, 216, 34}
	cases := map[string][]byte{
		"dns":       devicePacket(dev, 5000, pub, 53, []byte("q")),
		"private":   devicePacket(dev, 5000, [4]byte{10, 77, 0, 1}, 3074, []byte("x")),
		"lan":       devicePacket(dev, 5000, [4]byte{192, 168, 1, 1}, 3074, []byte("x")),
		"multicast": devicePacket(dev, 5000, [4]byte{239, 1, 1, 1}, 3074, []byte("x")),
	}
	tcp := devicePacket(dev, 5000, pub, 443, []byte("x"))
	tcp[9] = 6
	cases["tcp"] = tcp
	frag := devicePacket(dev, 5000, pub, 3074, []byte("x"))
	frag[6] = 0x20
	cases["fragment"] = frag
	for name, p := range cases {
		if d.Handle(p) {
			t.Fatal(name, "must stay in the tunnel")
		}
	}
	if (*directUDP)(nil).Handle(cases["dns"]) {
		t.Fatal("nil passthrough must decline")
	}
}
