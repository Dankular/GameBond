package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// directUDP is the passthrough for a connected device's game traffic: UDP the
// device sends to a public address leaves through an uplink socket on this
// machine (a userspace NAT keyed by the device's source port, so the mapping is
// endpoint independent like a home router) and replies are injected back to
// the device. Nothing enters the bonding tunnel. TCP and anything it cannot
// carry (fragments, DNS, private or multicast destinations) return false so
// the caller tunnels it as before.
type directUDP struct {
	open    func() (*net.UDPConn, error)
	deliver func([]byte) bool
	allow   func(netip.Addr) bool
	now     func() time.Time

	mu    sync.Mutex
	socks map[[6]byte]*directSock // device IPv4 + source port

	sent, received, dropped, flows atomic.Uint64
	ident                          atomic.Uint32
}

type directSock struct {
	conn *net.UDPConn
	last atomic.Int64
}

const directIdle = 120 * time.Second

func newDirectUDP(open func() (*net.UDPConn, error), deliver func([]byte) bool) *directUDP {
	return &directUDP{open: open, deliver: deliver, allow: publicV4, now: time.Now, socks: map[[6]byte]*directSock{}}
}

// publicV4 is true for destinations that belong on the internet.
func publicV4(a netip.Addr) bool {
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLinkLocalUnicast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// Handle sends the device packet directly. It reports false when the packet is
// not eligible or the direct path failed, and the caller must tunnel it.
func (d *directUDP) Handle(p []byte) bool {
	if d == nil || len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
		return false
	}
	ihl := int(p[0]&15) * 4
	if ihl < 20 || len(p) < ihl+8 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return false
	}
	udpLen := int(binary.BigEndian.Uint16(p[ihl+4:]))
	if udpLen < 8 || ihl+udpLen > len(p) {
		return false
	}
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	sport, dport := binary.BigEndian.Uint16(p[ihl:]), binary.BigEndian.Uint16(p[ihl+2:])
	if dport == 53 || !d.allow(dst) {
		return false
	}
	var key [6]byte
	copy(key[:4], p[12:16])
	binary.BigEndian.PutUint16(key[4:], sport)
	s := d.sock(key, [4]byte(p[12:16]), sport)
	if s == nil {
		d.dropped.Add(1)
		return false
	}
	s.last.Store(d.now().UnixNano())
	if _, err := s.conn.WriteToUDPAddrPort(p[ihl+8:ihl+udpLen], netip.AddrPortFrom(dst, dport)); err != nil {
		d.dropped.Add(1)
		return false
	}
	d.sent.Add(1)
	return true
}

func (d *directUDP) sock(key [6]byte, dev [4]byte, sport uint16) *directSock {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s := d.socks[key]; s != nil {
		return s
	}
	conn, err := d.open()
	if err != nil {
		return nil
	}
	s := &directSock{conn: conn}
	s.last.Store(d.now().UnixNano())
	d.socks[key] = s
	d.flows.Add(1)
	go d.read(key, s, dev, sport)
	return s
}

// read injects every datagram the socket receives, from any remote, back to
// the device as if sent by that remote, and retires the socket when idle.
func (d *directUDP) read(key [6]byte, s *directSock, dev [4]byte, sport uint16) {
	buf := make([]byte, 2048)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && d.now().UnixNano()-s.last.Load() < int64(directIdle) {
				continue
			}
			d.mu.Lock()
			if d.socks[key] == s {
				delete(d.socks, key)
			}
			d.mu.Unlock()
			_ = s.conn.Close()
			return
		}
		if n > 1472 || !from.Addr().Is4() {
			d.dropped.Add(1)
			continue
		}
		s.last.Store(d.now().UnixNano())
		if d.deliver(d.build(from, dev, sport, buf[:n])) {
			d.received.Add(1)
		}
	}
}

// build makes the IPv4/UDP packet the device would see from the remote.
func (d *directUDP) build(from netip.AddrPort, dev [4]byte, dport uint16, payload []byte) []byte {
	total := 28 + len(payload)
	p := make([]byte, total)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	binary.BigEndian.PutUint16(p[4:], uint16(d.ident.Add(1)))
	binary.BigEndian.PutUint16(p[6:], 0x4000)
	src := from.Addr().As4()
	copy(p[12:16], src[:])
	copy(p[16:20], dev[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:], from.Port())
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload) // UDP checksum 0: not computed, valid for IPv4
	return p
}

func (d *directUDP) stats() map[string]any {
	d.mu.Lock()
	active := len(d.socks)
	d.mu.Unlock()
	return map[string]any{"sent": d.sent.Load(), "received": d.received.Load(), "dropped": d.dropped.Load(), "flows_opened": d.flows.Load(), "flows_active": active}
}

func (d *directUDP) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, s := range d.socks {
		_ = s.conn.Close()
		delete(d.socks, k)
	}
}
