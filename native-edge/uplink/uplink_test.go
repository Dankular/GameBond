package uplink

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestOpenBindsLocalAddressAndExchangesDatagrams(t *testing.T) {
	a, err := Open(Spec{Addr: netip.MustParseAddr("127.0.0.1"), Buffer: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(Spec{Addr: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.LocalAddr().(*net.UDPAddr).Port == b.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("uplinks must get distinct ports")
	}
	if _, err := a.WriteToUDP([]byte("hi"), b.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	n, from, err := b.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "hi" || !from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("got %q from %v err %v", buf[:n], from, err)
	}
}

func TestOpenPinsToAnInterfaceOrReportsWhy(t *testing.T) {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback == 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		c, err := Open(Spec{Interface: ifc.Name})
		if err != nil {
			t.Skipf("pinning to %s not permitted here: %v", ifc.Name, err)
		}
		c.Close()
		return
	}
	t.Skip("no loopback interface")
}

func TestOpenRejectsBadSpecs(t *testing.T) {
	if _, err := Open(Spec{Addr: netip.MustParseAddr("::1")}); err == nil {
		t.Fatal("IPv6 accepted")
	}
	if _, err := Open(Spec{Interface: "no-such-adapter0"}); err == nil {
		t.Fatal("unknown interface accepted")
	}
}

func TestInterfaceForFindsTheOwningAdapter(t *testing.T) {
	index, name, err := InterfaceFor(netip.MustParseAddr("127.0.0.1"))
	if err != nil || index == 0 || name == "" {
		t.Fatalf("loopback owner: %d %q %v", index, name, err)
	}
	ifc, err := net.InterfaceByIndex(index)
	if err != nil || ifc.Name != name {
		t.Fatalf("index %d does not name %q: %v", index, name, err)
	}
	if _, _, err = InterfaceFor(netip.MustParseAddr("203.0.113.77")); err == nil {
		t.Fatal("an address no adapter owns was resolved")
	}
}

func TestDontFragmentIsAppliedAndReported(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	plain, err := Open(Spec{Addr: lo})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if DFEnforced(plain) {
		t.Error("don't-fragment reported on a socket that did not ask for it")
	}
	df, err := Open(Spec{Addr: lo, DontFragment: true})
	if err != nil {
		t.Fatal(err)
	}
	defer df.Close()
	if !DFEnforced(df) {
		t.Error("don't-fragment not set")
	}
}
