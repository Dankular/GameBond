package main

import (
	"net/netip"
	"testing"
	"time"

	"gamebond.local/nativeedge/lan"
)

type fakeAdapter struct{ in chan []byte }

func (f *fakeAdapter) MAC() [6]byte       { return [6]byte{2, 0, 0, 0, 0, 1} }
func (f *fakeAdapter) Write([]byte) error { return nil }
func (f *fakeAdapter) Close() error       { return nil }
func (f *fakeAdapter) Read(t time.Duration) ([]byte, error) {
	select {
	case b := <-f.in:
		return b, nil
	case <-time.After(t):
		return nil, nil
	}
}

func dhcpFrame(mac byte) []byte {
	f := make([]byte, 14+20+8+4)
	copy(f[6:], []byte{2, 0, 0, 0, 0, mac})
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	f[23] = 17
	f[14+20+2], f[14+20+3] = 0, 67
	return f
}

func TestSharedAdapterClaimsByDHCP(t *testing.T) {
	fa := &fakeAdapter{in: make(chan []byte, 16)}
	s := newSharedAdapters(func(lan.DeviceConfig) (lan.FrameIO, error) { return fa, nil })
	a, _ := s.Open(lan.DeviceConfig{InterfaceID: "x", TunnelIP: netip.MustParseAddr("10.77.0.3")})
	b, _ := s.Open(lan.DeviceConfig{InterfaceID: "X", TunnelIP: netip.MustParseAddr("10.77.0.4")})
	fa.in <- dhcpFrame(0xA1)
	fa.in <- dhcpFrame(0xB2)
	fa.in <- dhcpFrame(0xB2)
	fa.in <- dhcpFrame(0xA1)
	read := func(v lan.FrameIO) (n int, mac byte) {
		for {
			f, _ := v.Read(100 * time.Millisecond)
			if f == nil {
				return
			}
			n++
			mac = f[11]
		}
	}
	if n, m := read(a); n != 2 || m != 0xA1 {
		t.Fatalf("view a got %d frames mac %x", n, m)
	}
	if n, m := read(b); n != 2 || m != 0xB2 {
		t.Fatalf("view b got %d frames mac %x", n, m)
	}
}
