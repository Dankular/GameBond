package lan

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	testDevice  = [4]byte{10, 77, 0, 4}
	testGateway = [4]byte{10, 77, 0, 1}
	macLaptop   = [6]byte{0x9e, 0xb8, 0x14, 0xe2, 0x7d, 0x98}
	macOther    = [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
)

// dhcpFrame builds a client DHCP message of the given kind from mac.
func dhcpFrame(mac [6]byte, kind byte, ciaddr, requested [4]byte) []byte {
	p := make([]byte, 240)
	p[0], p[1], p[2] = 1, 1, 6
	copy(p[4:], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(p[12:16], ciaddr[:])
	copy(p[28:34], mac[:])
	copy(p[236:], []byte{0x63, 0x82, 0x53, 0x63})
	p = append(p, 53, 1, kind)
	if requested != [4]byte{} {
		p = append(p, 50, 4)
		p = append(p, requested[:]...)
		p = append(p, 54, 4)
		p = append(p, testGateway[:]...)
	}
	p = append(p, 255)
	udp := buildUDP([4]byte{}, [4]byte{255, 255, 255, 255}, 68, 67, p)
	ip := buildIPv4([4]byte{}, [4]byte{255, 255, 255, 255}, 17, udp, 1)
	frame := append(append(append([]byte{}, broadcastMAC[:]...), mac[:]...), 0x08, 0x00)
	return append(frame, ip...)
}

// arpReplyFrame is the device answering the gateway's ARP probe.
func arpReplyFrame(gwMAC, mac [6]byte, ip [4]byte) []byte {
	b := append([]byte{0, 1, 8, 0, 6, 4, 0, 2}, mac[:]...)
	b = append(append(append(b, ip[:]...), gwMAC[:]...), testGateway[:]...)
	frame := append(append(append([]byte{}, gwMAC[:]...), mac[:]...), 0x08, 0x06)
	return append(frame, b...)
}

type leaseFixture struct {
	now   time.Time
	path  string
	io    *fakeIO
	g     *Gateway
	table *LeaseTable
}

// boot starts a gateway for the unpinned laptop over the table at path, the way a
// client restart does.
func boot(t *testing.T, path string, now time.Time) *leaseFixture {
	t.Helper()
	f := &leaseFixture{now: now, path: path, io: &fakeIO{}}
	f.table = OpenLeaseTable(path)
	g, err := NewGateway(Config{
		Device:   Device{Name: "Laptop", TunnelIP: netip.AddrFrom4(testDevice)},
		ClientIP: netip.MustParseAddr("10.77.0.2"), Leases: f.table, LeaseSeconds: 3600, StaleAfter: time.Minute,
		Now: func() time.Time { return f.now }, OnPacket: func([]byte) {},
	}, f.io)
	if err != nil {
		t.Fatal(err)
	}
	f.g = g
	return f
}

func (f *leaseFixture) request(t *testing.T, mac [6]byte) {
	t.Helper()
	f.g.HandleFrame(dhcpFrame(mac, 3, [4]byte{}, testDevice))
}

func TestLeaseSurvivesRestartWithoutDHCP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	start := time.Unix(1_800_000_000, 0)
	a := boot(t, path, start)
	a.request(t, macLaptop)
	if !a.g.IsLeased() || a.g.Stats().DHCPAcks != 1 {
		t.Fatalf("first boot: leased=%v acks=%d", a.g.IsLeased(), a.g.Stats().DHCPAcks)
	}
	row, ok := a.table.Get("Laptop", netip.AddrFrom4(testDevice))
	if !ok || row.MAC != "9e:b8:14:e2:7d:98" || !row.Leased || row.Expires != start.Unix()+3600 {
		t.Fatalf("lease table row wrong: %+v", row)
	}

	// Restart 10 minutes later: a new table loaded from disk and a new gateway.
	b := boot(t, path, start.Add(10*time.Minute))
	if b.g.Present() || b.g.IsLeased() {
		t.Fatal("device reported present before it was heard from")
	}
	if !b.g.Leased {
		t.Fatal("unexpired lease was not restored from the table")
	}
	if mac, ok := b.g.DeviceMAC(); !ok || mac != macLaptop {
		t.Fatal("last MAC not restored")
	}
	// The gateway goes looking for the device straight away.
	b.g.ProbeDevice()
	if len(b.io.out) != 1 {
		t.Fatalf("no ARP probe sent to the remembered MAC: %d frames", len(b.io.out))
	}
	frame, _ := hex.DecodeString(b.io.out[0])
	var dst [6]byte
	copy(dst[:], frame[:6])
	if dst != macLaptop || binary.BigEndian.Uint16(frame[12:]) != 0x0806 {
		t.Fatalf("probe not unicast ARP to the laptop: %x", frame[:14])
	}
	// The laptop answers: adopted with its lease, no DHCP exchange at all.
	b.g.HandleFrame(arpReplyFrame(b.g.mac, macLaptop, testDevice))
	if !b.g.Present() || !b.g.IsLeased() {
		t.Fatal("device not adopted from the ARP reply")
	}
	if b.g.Stats().DHCPAcks != 0 || b.g.Stats().DHCPOffers != 0 {
		t.Fatal("restart needed a DHCP exchange")
	}
}

func TestExpiredLeaseIsNotRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	start := time.Unix(1_800_000_000, 0)
	a := boot(t, path, start)
	a.request(t, macLaptop)
	b := boot(t, path, start.Add(2*time.Hour)) // lease was 1 h
	if b.g.Leased {
		t.Fatal("expired lease restored")
	}
	if mac, ok := b.g.DeviceMAC(); !ok || mac != macLaptop {
		t.Fatal("the MAC is still a useful hint after the lease lapses")
	}
}

func TestUnconfirmedHintNeverBlocksAnotherDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	start := time.Unix(1_800_000_000, 0)
	a := boot(t, path, start)
	a.request(t, macLaptop)
	b := boot(t, path, start.Add(time.Minute))
	// A different device (new laptop, phone with a private MAC) asks for the address.
	b.g.HandleFrame(dhcpFrame(macOther, 3, [4]byte{}, testDevice))
	if b.g.Stats().ForeignMACDropped != 0 || b.g.Stats().DHCPAcks != 1 {
		t.Fatalf("hint blocked a new device: %+v", b.g.Stats())
	}
	if mac, _ := b.g.DeviceMAC(); mac != macOther {
		t.Fatal("new device did not take the address")
	}
	row, _ := b.table.Get("Laptop", netip.AddrFrom4(testDevice))
	if row.MAC != "02:11:22:33:44:55" {
		t.Fatalf("table not updated to the new holder: %+v", row)
	}
	// Once confirmed, the holder is protected again from a third device.
	b.g.HandleFrame(dhcpFrame(macLaptop, 3, [4]byte{}, testDevice))
	if b.g.Stats().ForeignMACDropped != 1 {
		t.Fatal("a confirmed holder was displaced inside the stale window")
	}
}

func TestReleaseGivesTheAddressBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	start := time.Unix(1_800_000_000, 0)
	a := boot(t, path, start)
	a.request(t, macLaptop)
	a.g.HandleFrame(dhcpFrame(macLaptop, 7, testDevice, [4]byte{}))
	if a.g.Leased || a.g.Stats().DHCPReleases != 1 {
		t.Fatal("release ignored")
	}
	row, _ := a.table.Get("Laptop", netip.AddrFrom4(testDevice))
	if row.Leased {
		t.Fatal("released lease still saved as held")
	}
	if b := boot(t, path, start.Add(time.Minute)); b.g.Leased {
		t.Fatal("released lease came back after a restart")
	}
	// A release from someone else changes nothing.
	c := boot(t, path, start)
	c.request(t, macLaptop)
	c.g.HandleFrame(dhcpFrame(macOther, 7, testDevice, [4]byte{}))
	if !c.g.Leased {
		t.Fatal("a stranger released the lease")
	}
}

func TestCorruptOrMissingTableStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	if rows := OpenLeaseTable(filepath.Join(dir, "none.json")).Rows(); len(rows) != 0 {
		t.Fatal("missing file produced rows")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := boot(t, bad, time.Unix(1_800_000_000, 0))
	f.request(t, macLaptop) // still works, and rewrites the file cleanly
	if rows := OpenLeaseTable(bad).Rows(); len(rows) != 1 {
		t.Fatalf("table not rebuilt after corruption: %v", rows)
	}
}

func TestPinnedDeviceKeepsItsLeaseAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	start := time.Unix(1_800_000_000, 0)
	mk := func(now time.Time) *leaseFixture {
		f := &leaseFixture{now: now, io: &fakeIO{}, table: OpenLeaseTable(path)}
		pin := macLaptop
		g, err := NewGateway(Config{
			Device:   Device{Name: "Laptop", TunnelIP: netip.AddrFrom4(testDevice), PinnedMAC: &pin},
			ClientIP: netip.MustParseAddr("10.77.0.2"), Leases: f.table, LeaseSeconds: 3600,
			Now: func() time.Time { return f.now }, OnPacket: func([]byte) {},
		}, f.io)
		if err != nil {
			t.Fatal(err)
		}
		f.g = g
		return f
	}
	a := mk(start)
	a.request(t, macLaptop)
	b := mk(start.Add(5 * time.Minute))
	if !b.g.Leased || !b.g.IsLeased() {
		t.Fatal("pinned device lost its lease on restart")
	}
}
