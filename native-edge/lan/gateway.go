package lan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ethIPv4        = 0x0800
	ethARP         = 0x0806
	DeviceMTU      = 1500
	DefaultLease   = 86400
	DefaultStale   = 120 * time.Second
	DefaultTunnelM = 1280
)

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// IO is raw Ethernet frame access for one adapter.
type IO interface {
	MAC() [6]byte
	Write(frame []byte) error
}

// Device is one device-facing adapter and the tunnel address its device receives.
type Device struct {
	Name      string
	TunnelIP  netip.Addr
	PinnedMAC *[6]byte
	DNS       []netip.Addr
}

// Config are the gateway parameters (client_tunnel_ip etc. in Python).
type Config struct {
	// Leases persists the DHCP lease table across restarts (nil: memory only).
	Leases       *LeaseTable
	Device       Device
	ClientIP     netip.Addr
	GatewayIP    netip.Addr // zero: network address + 1
	TunnelMTU    int
	LeaseSeconds int
	StaleAfter   time.Duration
	Now          func() time.Time
	OnPacket     func([]byte)
}

// Counters mirror the Python counter names.
type Counters struct {
	BytesToTunnel, BytesFromTunnel, FramesIn, FramesOut, PacketsToTunnel, PacketsFromTunnel, DHCPOffers, DHCPAcks, DHCPNaks, DHCPReleases uint64
	ARPReplies, ForeignMACDropped, SpoofedSourceDropped, LocalOnlyDropped, TTLExpired, Fragmented                                         uint64
	FragNeededSent, WrongDestination, NoDeviceMAC, Malformed, WriteErrors                                                                 uint64
}

// Gateway serves one device on one adapter. Methods are safe for concurrent
// use; HandleFrame calls are serialised.
type Gateway struct {
	// Timing of tunnel-to-device delivery: time waiting for mu and time inside the
	// adapter write, worst case in ns and counts over 10 ms (see Timing).
	delivLockMax, delivWriteMax, delivLockOver10, delivWriteOver10 atomic.Int64
	mu        sync.Mutex
	cfg       Config
	io        IO
	mac       [6]byte
	prefix    netip.Prefix
	gateway   [4]byte
	device    [4]byte
	deviceMAC *[6]byte
	lastSeen  time.Time
	hasSeen   bool
	hinted    bool // deviceMAC came from the lease table and has not spoken yet
	leaseEnd  time.Time
	saved     Lease
	mssLimit  int
	ident     uint16
	Leased    bool
	c         Counters
	probe     probeState
}

func subnetOf(ip netip.Addr) netip.Prefix { p, _ := ip.Prefix(24); return p }

// NewGateway validates the device against the client tunnel /24 like
// LanDevice.validate and builds the gateway.
func NewGateway(cfg Config, io IO) (*Gateway, error) {
	if !cfg.ClientIP.Is4() || !cfg.Device.TunnelIP.Is4() {
		return nil, errors.New("tunnel addresses must be IPv4")
	}
	subnet := subnetOf(cfg.ClientIP)
	ip := cfg.Device.TunnelIP
	base := subnet.Addr().As4()
	b := ip.As4()
	if !subnet.Contains(ip) || b[3] == 0 || b[3] == 1 || b[3] == 255 || ip == cfg.ClientIP {
		return nil, fmt.Errorf("%s is not a usable device address in %s (not .0, .1, .255 or the client address)", ip, subnet)
	}
	_ = base
	if len(cfg.Device.DNS) == 0 {
		cfg.Device.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	}
	if len(cfg.Device.DNS) > 3 {
		return nil, errors.New("LAN device dns must list one to three unicast IPv4 addresses")
	}
	for _, d := range cfg.Device.DNS {
		if !d.Is4() || d.IsUnspecified() || d.IsLoopback() || d.IsMulticast() || d.IsLinkLocalUnicast() || d == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return nil, errors.New("LAN device dns must list one to three unicast IPv4 addresses")
		}
	}
	if cfg.TunnelMTU == 0 {
		cfg.TunnelMTU = DefaultTunnelM
	}
	if cfg.LeaseSeconds == 0 {
		cfg.LeaseSeconds = DefaultLease
	}
	if cfg.StaleAfter == 0 {
		cfg.StaleAfter = DefaultStale
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	gw := cfg.GatewayIP
	if !gw.IsValid() {
		a := subnet.Addr().As4()
		a[3]++
		gw = netip.AddrFrom4(a)
	}
	g := &Gateway{cfg: cfg, io: io, mac: io.MAC(), prefix: subnet, gateway: gw.As4(), device: ip.As4(), mssLimit: cfg.TunnelMTU - 40}
	row, haveRow := cfg.Leases.Get(cfg.Device.Name, ip)
	if haveRow {
		g.saved = row
		if row.Active(cfg.Now()) {
			g.Leased, g.leaseEnd = true, time.Unix(row.Expires, 0)
		}
	}
	if cfg.Device.PinnedMAC != nil {
		m := *cfg.Device.PinnedMAC
		g.deviceMAC = &m
		g.lastSeen, g.hasSeen = cfg.Now(), true
	} else if haveRow {
		// Last known holder of the address: probed at once, but only a hint, so any
		// other device may still claim the address until this one is heard from.
		if m, err := ParseMAC(row.MAC); err == nil {
			g.deviceMAC, g.hinted = &m, true
		}
	}
	return g, nil
}

// PresenceTimeout is how long a device may stay silent before it is treated as
// disconnected (powered off or unplugged). A running console sends frames
// constantly, so silence this long means it is gone.
const PresenceTimeout = 30 * time.Second

// IsLeased reports whether the device has its address and is still on the
// wire. A device that stops sending for PresenceTimeout is disconnected and
// has to ask for an address again when it returns.
func (g *Gateway) IsLeased() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.Leased && g.presentLocked() && (g.leaseEnd.IsZero() || g.cfg.Now().Before(g.leaseEnd))
}

// Present reports whether the device has sent a frame within PresenceTimeout.
func (g *Gateway) Present() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.presentLocked()
}

// SilentFor is how long since the device last sent a frame; zero if never seen.
func (g *Gateway) SilentFor() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.hasSeen {
		return 0
	}
	return g.cfg.Now().Sub(g.lastSeen)
}

func (g *Gateway) presentLocked() bool {
	return g.hasSeen && g.cfg.Now().Sub(g.lastSeen) < PresenceTimeout
}

func (g *Gateway) Stats() Counters {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.c
}

// Announce broadcasts a gratuitous ARP for the gateway address so devices refresh
// their neighbour cache and know the gateway is back.
func (g *Gateway) Announce() {
	g.mu.Lock()
	defer g.mu.Unlock()
	req := append([]byte{0, 1, 8, 0, 6, 4, 0, 1}, g.mac[:]...)
	req = append(append(append(req, g.gateway[:]...), make([]byte, 6)...), g.gateway[:]...)
	g.sendFrame(broadcastMAC, ethARP, req)
}

// DeviceMAC returns the learned or pinned device MAC.
func (g *Gateway) DeviceMAC() (mac [6]byte, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.deviceMAC == nil {
		return mac, false
	}
	return *g.deviceMAC, true
}

func (g *Gateway) stale() bool {
	if g.cfg.Device.PinnedMAC != nil {
		return false
	}
	if g.hinted && !g.hasSeen {
		return true // an unconfirmed hint never blocks a real device
	}
	return g.hasSeen && g.cfg.Now().Sub(g.lastSeen) >= g.cfg.StaleAfter
}

func (g *Gateway) mayClaim(src [6]byte) bool {
	if g.deviceMAC != nil && src == *g.deviceMAC {
		return true
	}
	return g.cfg.Device.PinnedMAC == nil && (g.deviceMAC == nil || g.stale())
}

func (g *Gateway) touch(src [6]byte) {
	m := src
	g.deviceMAC, g.lastSeen, g.hasSeen = &m, g.cfg.Now(), true
	if g.hinted {
		g.hinted = false
	}
	if fmtMAC(src) != g.saved.MAC {
		g.persist(0)
	}
}

func fmtMAC(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// persist writes the device's row to the lease table. grantedAt is the unix time
// of a fresh ACK, or 0 to keep the existing grant.
func (g *Gateway) persist(grantedAt int64) {
	if g.cfg.Leases == nil || g.deviceMAC == nil {
		return
	}
	row := Lease{Name: g.cfg.Device.Name, IP: netip.AddrFrom4(g.device).String(), MAC: fmtMAC(*g.deviceMAC),
		Leased: g.Leased, Granted: g.saved.Granted, Expires: g.saved.Expires}
	if grantedAt != 0 {
		row.Granted, row.Expires = grantedAt, g.leaseEnd.Unix()
	}
	if !g.Leased {
		row.Expires = g.saved.Expires
	}
	g.saved = row
	g.cfg.Leases.Put(row)
}

// Lease is this device's row of the lease table.
func (g *Gateway) Lease() (Lease, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.saved, g.saved.MAC != ""
}

// HandleFrame processes one Ethernet frame from the device-facing adapter.
func (g *Gateway) HandleFrame(frame []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.c.FramesIn++
	if len(frame) < 14 {
		g.c.Malformed++
		return
	}
	var dst, src [6]byte
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])
	et := binary.BigEndian.Uint16(frame[12:])
	if src == g.mac || (dst != g.mac && dst != broadcastMAC) {
		return
	}
	switch et {
	case ethARP:
		g.arp(src, frame[14:])
	case ethIPv4:
		g.ipv4(src, frame[14:])
	}
}

func (g *Gateway) arp(srcMAC [6]byte, body []byte) {
	if len(body) < 28 || !bytes.Equal(body[:6], []byte{0, 1, 8, 0, 6, 4}) {
		g.c.Malformed++
		return
	}
	op := binary.BigEndian.Uint16(body[6:])
	var senderMAC [6]byte
	var senderIP, targetIP [4]byte
	copy(senderMAC[:], body[8:14])
	copy(senderIP[:], body[14:18])
	copy(targetIP[:], body[24:28])
	if senderMAC != srcMAC || (op != 1 && op != 2) {
		g.c.Malformed++
		return
	}
	switch senderIP {
	case g.device:
		if !g.mayClaim(srcMAC) {
			g.c.ForeignMACDropped++
			return
		}
		g.touch(srcMAC)
	case [4]byte{}:
		if g.deviceMAC != nil && srcMAC != *g.deviceMAC && !g.stale() {
			g.c.ForeignMACDropped++
			return
		}
	default:
		g.c.SpoofedSourceDropped++
		return
	}
	if op == 2 && senderIP == g.device && targetIP == g.gateway {
		g.probe.reply(g.cfg.Now())
		return
	}
	if op != 1 {
		return
	}
	target := netip.AddrFrom4(targetIP)
	broadcast := g.prefix.Addr().As4()
	broadcast[3] = 255
	if targetIP == g.device || !g.prefix.Contains(target) || targetIP == broadcast {
		return
	}
	reply := append([]byte{0, 1, 8, 0, 6, 4, 0, 2}, g.mac[:]...)
	reply = append(append(append(reply, targetIP[:]...), senderMAC[:]...), senderIP[:]...)
	g.sendFrame(srcMAC, ethARP, reply)
	g.c.ARPReplies++
}

func (g *Gateway) ipv4(srcMAC [6]byte, packet []byte) {
	header, protocol, src, dst, total, ok := parseIPv4(packet)
	if !ok {
		g.c.Malformed++
		return
	}
	packet = packet[:total]
	if protocol == 17 && total >= header+8 && binary.BigEndian.Uint16(packet[header+2:]) == 67 {
		g.dhcp(srcMAC, packet[header+8:])
		return
	}
	if !g.mayClaim(srcMAC) {
		g.c.ForeignMACDropped++
		return
	}
	if src != g.device {
		g.c.SpoofedSourceDropped++
		return
	}
	g.touch(srcMAC)
	d := netip.AddrFrom4(dst)
	broadcast := g.prefix.Addr().As4()
	broadcast[3] = 255
	if d.IsMulticast() || d.IsUnspecified() || d.IsLoopback() || dst == [4]byte{255, 255, 255, 255} || dst == broadcast || dst == g.device {
		g.c.LocalOnlyDropped++
		return
	}
	fwd := decrementTTL(packet)
	if fwd == nil {
		g.c.TTLExpired++
		return
	}
	fwd = clampTCPMSS(fwd, g.mssLimit)
	var pieces [][]byte
	if len(fwd) > g.cfg.TunnelMTU {
		if binary.BigEndian.Uint16(fwd[6:])&0x4000 != 0 {
			g.fragNeeded(fwd)
			return
		}
		pieces = fragmentIPv4(fwd, g.cfg.TunnelMTU)
		g.c.Fragmented++
	} else {
		pieces = [][]byte{fwd}
	}
	for _, p := range pieces {
		g.c.PacketsToTunnel++
		g.c.BytesToTunnel += uint64(len(p))
		g.cfg.OnPacket(p)
	}
}

func (g *Gateway) dhcp(srcMAC [6]byte, p []byte) {
	if len(p) < 240 || p[0] != 1 || p[1] != 1 || p[2] != 6 || !bytes.Equal(p[236:240], []byte{0x63, 0x82, 0x53, 0x63}) {
		g.c.Malformed++
		return
	}
	var chaddr [6]byte
	copy(chaddr[:], p[28:34])
	if chaddr != srcMAC {
		g.c.Malformed++
		return
	}
	opts := map[byte][]byte{}
	for i := 240; i < len(p); {
		kind := p[i]
		if kind == 255 {
			break
		}
		if kind == 0 {
			i++
			continue
		}
		if i+1 >= len(p) || i+2+int(p[i+1]) > len(p) {
			break
		}
		opts[kind] = p[i+2 : i+2+int(p[i+1])]
		i += 2 + int(p[i+1])
	}
	kind := byte(0) // Python raises IndexError on an empty option 53; here it is ignored
	if v := opts[53]; len(v) > 0 {
		kind = v[0]
	}
	if kind == 7 { // DHCPRELEASE: the device gives its address back
		if g.deviceMAC != nil && srcMAC == *g.deviceMAC && bytes.Equal(p[12:16], g.device[:]) {
			g.Leased, g.leaseEnd = false, time.Time{}
			g.persist(0)
			g.c.DHCPReleases++
		}
		return
	}
	if kind != 1 && kind != 3 {
		return
	}
	if g.cfg.Device.PinnedMAC != nil {
		if srcMAC != *g.cfg.Device.PinnedMAC {
			g.c.ForeignMACDropped++
			return
		}
	} else if g.deviceMAC != nil && srcMAC != *g.deviceMAC && !g.stale() {
		g.c.ForeignMACDropped++
		return
	}
	g.touch(srcMAC)
	xid, flags := p[4:8], p[10:12]
	if kind == 1 {
		g.dhcpReply(2, xid, flags, chaddr, g.device)
		g.c.DHCPOffers++
		return
	}
	if server, ok := opts[54]; ok && !bytes.Equal(server, g.gateway[:]) {
		return
	}
	requested := opts[50]
	if len(requested) == 0 && !bytes.Equal(p[12:16], []byte{0, 0, 0, 0}) {
		requested = p[12:16]
	}
	if bytes.Equal(requested, g.device[:]) {
		g.dhcpReply(5, xid, flags, chaddr, g.device)
		g.c.DHCPAcks++
		g.Leased = true
		g.leaseEnd = g.cfg.Now().Add(time.Duration(g.cfg.LeaseSeconds) * time.Second)
		g.persist(g.cfg.Now().Unix())
	} else {
		g.dhcpReply(6, xid, flags, chaddr, [4]byte{})
		g.c.DHCPNaks++
	}
}

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func (g *Gateway) dhcpReply(message byte, xid, flags []byte, chaddr [6]byte, yiaddr [4]byte) {
	body := make([]byte, 0, 300)
	body = append(body, 2, 1, 6, 0)
	body = append(body, xid...)
	body = append(body, 0, 0)
	body = append(body, flags...)
	body = append(body, 0, 0, 0, 0)
	body = append(body, yiaddr[:]...)
	body = append(body, g.gateway[:]...)
	body = append(body, 0, 0, 0, 0)
	body = append(body, chaddr[:]...)
	body = append(body, make([]byte, 10+64+128)...)
	body = append(body, 0x63, 0x82, 0x53, 0x63)
	opt := []byte{53, 1, message, 54, 4}
	opt = append(opt, g.gateway[:]...)
	if message != 6 {
		l := uint32(g.cfg.LeaseSeconds)
		opt = append(append(opt, 51, 4), be32(l)...)
		opt = append(append(opt, 58, 4), be32(l/2)...)
		opt = append(append(opt, 59, 4), be32(l*7/8)...)
		opt = append(opt, 1, 4, 255, 255, 255, 0)
		opt = append(append(opt, 3, 4), g.gateway[:]...)
		dns := []byte{}
		for _, d := range g.cfg.Device.DNS {
			a := d.As4()
			dns = append(dns, a[:]...)
		}
		opt = append(append(opt, 6, byte(len(dns))), dns...)
		opt = append(opt, 26, 2, byte(g.cfg.TunnelMTU>>8), byte(g.cfg.TunnelMTU))
		bc := g.prefix.Addr().As4()
		bc[3] = 255
		opt = append(append(opt, 28, 4), bc[:]...)
	}
	opt = append(opt, 255)
	udp := buildUDP(g.gateway, [4]byte{255, 255, 255, 255}, 67, 68, append(body, opt...))
	g.sendFrame(broadcastMAC, ethIPv4, buildIPv4(g.gateway, [4]byte{255, 255, 255, 255}, 17, udp, g.nextIdent()))
}

// Deliver sends a packet received from the VPS to the device.
func (g *Gateway) Deliver(packet []byte) bool {
	t0 := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	noteDeliveryMax(&g.delivLockMax, &g.delivLockOver10, time.Since(t0))
	_, _, _, dst, total, ok := parseIPv4(packet)
	if !ok {
		g.c.Malformed++
		return false
	}
	if dst != g.device {
		g.c.WrongDestination++
		return false
	}
	if g.deviceMAC == nil {
		g.c.NoDeviceMAC++
		return false
	}
	p := decrementTTL(packet[:total])
	if p == nil {
		g.c.TTLExpired++
		return false
	}
	p = clampTCPMSS(p, g.mssLimit)
	if len(p) > DeviceMTU {
		g.c.Malformed++
		return false
	}
	g.c.PacketsFromTunnel++
	g.c.BytesFromTunnel += uint64(len(p))
	t1 := time.Now()
	ok = g.sendFrame(*g.deviceMAC, ethIPv4, p)
	noteDeliveryMax(&g.delivWriteMax, &g.delivWriteOver10, time.Since(t1))
	return ok
}

func noteDeliveryMax(max, over10 *atomic.Int64, d time.Duration) {
	if d > 10*time.Millisecond {
		over10.Add(1)
	}
	for {
		cur := max.Load()
		if int64(d) <= cur || max.CompareAndSwap(cur, int64(d)) {
			return
		}
	}
}

// DeliveryTiming reports worst-case milliseconds spent waiting for the gateway lock and
// inside the adapter write on the tunnel-to-device path, and how often each passed 10 ms.
func (g *Gateway) DeliveryTiming() map[string]any {
	ms := func(v int64) float64 { return float64(v) / 1e6 }
	return map[string]any{"lock_wait_max_ms": ms(g.delivLockMax.Load()), "lock_wait_over_10ms": g.delivLockOver10.Load(),
		"adapter_write_max_ms": ms(g.delivWriteMax.Load()), "adapter_write_over_10ms": g.delivWriteOver10.Load()}
}

func (g *Gateway) fragNeeded(original []byte) {
	header := int(original[0]&15) * 4
	quoted := original[:min(len(original), header+8)]
	icmp := append([]byte{3, 4, 0, 0, 0, 0, byte(g.cfg.TunnelMTU >> 8), byte(g.cfg.TunnelMTU)}, quoted...)
	binary.BigEndian.PutUint16(icmp[2:], checksum(icmp, 0))
	if g.deviceMAC != nil {
		g.sendFrame(*g.deviceMAC, ethIPv4, buildIPv4(g.gateway, g.device, 1, icmp, g.nextIdent()))
		g.c.FragNeededSent++
	}
}

func (g *Gateway) nextIdent() uint16 { g.ident++; return g.ident }

func (g *Gateway) sendFrame(dst [6]byte, ethertype uint16, payload []byte) bool {
	frame := append(append(append([]byte{}, dst[:]...), g.mac[:]...), byte(ethertype>>8), byte(ethertype))
	frame = append(frame, payload...)
	if len(frame) < 60 {
		frame = append(frame, make([]byte, 60-len(frame))...)
	}
	if err := g.io.Write(frame); err != nil {
		g.c.WriteErrors++
		return false
	}
	g.c.FramesOut++
	return true
}

type probeState struct {
	sentAt                    map[uint16]time.Time
	seq                       uint16
	Sent, Recv, Over5, Over20 uint64
	SumMS, MaxMS              float64
}

// reply credits an ARP reply to the oldest unanswered probe. ARP replies carry no
// sequence number, so matching only the newest probe made any reply slower than one
// probe interval look like loss (a phone on Wi-Fi power save, a busy console).
func (p *probeState) reply(now time.Time) {
	var seq uint16
	var t time.Time
	found := false
	for k, sent := range p.sentAt {
		if !found || sent.Before(t) {
			seq, t, found = k, sent, true
		}
	}
	if !found {
		return
	}
	delete(p.sentAt, seq)
	ms := float64(now.Sub(t)) / float64(time.Millisecond)
	p.Recv++
	p.SumMS += ms
	if ms > p.MaxMS {
		p.MaxMS = ms
	}
	if ms > 5 {
		p.Over5++
	}
	if ms > 20 {
		p.Over20++
	}
}

// ProbeDevice sends one unicast ARP request to the device so the adapter-to-device leg
// can be timed. It does nothing until the device's MAC is known.
func (g *Gateway) ProbeDevice() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.deviceMAC == nil {
		return
	}
	p := &g.probe
	if p.sentAt == nil {
		p.sentAt = map[uint16]time.Time{}
	}
	p.seq++
	for k, t := range p.sentAt { // forget probes that will never be answered
		if g.cfg.Now().Sub(t) > 2*time.Second {
			delete(p.sentAt, k)
		}
	}
	req := append([]byte{0, 1, 8, 0, 6, 4, 0, 1}, g.mac[:]...)
	req = append(append(append(req, g.gateway[:]...), g.deviceMAC[:]...), g.device[:]...)
	p.sentAt[p.seq] = g.cfg.Now()
	if g.sendFrame(*g.deviceMAC, ethARP, req) {
		p.Sent++
	}
}

// ProbeStats reports the device round trips seen so far.
func (g *Gateway) ProbeStats() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.probe
	mean := 0.0
	if p.Recv > 0 {
		mean = p.SumMS / float64(p.Recv)
	}
	return map[string]any{"sent": p.Sent, "received": p.Recv, "mean_ms": mean, "max_ms": p.MaxMS, "over_5ms": p.Over5, "over_20ms": p.Over20}
}
