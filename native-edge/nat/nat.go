// Package nat is the Go port of gamebond/nat.py: a stateful port-restricted
// cone source NAT for IPv4 TCP, UDP and ICMP echo (plus ICMP errors quoting a
// known mapping). Fragments, other ICMP types and other protocols are dropped
// and counted.
package nat

import (
	"container/list"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"net/netip"
	"sync"
	"time"
)

const (
	TCP  = 6
	UDP  = 17
	ICMP = 1

	icmpEchoReply   = 0
	icmpEchoRequest = 8

	UDPTimeout            = 120 * time.Second
	ICMPTimeout           = 30 * time.Second
	TCPEstablishedTimeout = 7200 * time.Second
	TCPOtherTimeout       = 120 * time.Second
	TCPClosingTimeout     = 30 * time.Second
	MaxRemotes            = 128
)

type fwdKey struct {
	proto byte
	ip    [4]byte
	port  uint16
}
type revKey struct {
	proto byte
	port  uint16
}
type remote struct {
	ip   [4]byte
	port uint16
}

type entry struct {
	proto   byte
	intIP   [4]byte
	intPort uint16
	extPort uint16
	remotes map[remote]*list.Element
	order   *list.List // remotes, oldest at the front
	last    time.Time
	state   string
	elem    *list.Element // position in Nat.order
}

func (e *entry) timeout() time.Duration {
	switch e.proto {
	case UDP:
		return UDPTimeout
	case ICMP:
		return ICMPTimeout
	}
	switch e.state {
	case "est":
		return TCPEstablishedTimeout
	case "closing":
		return TCPClosingTimeout
	}
	return TCPOtherTimeout
}

// Counters mirror the Python counter names.
type Counters struct {
	Out, In, Created, Expired, Evicted, Fragments, Unsupported, Malformed uint64
	NoMapping, Filtered, PortExhausted, NotForUs, ICMPErrors              uint64
	Active                                                                int
}

// Nat translates between the internal addresses and one external address.
type Nat struct {
	mu         sync.Mutex
	external   [4]byte
	maxEntries int
	low, high  int
	Now        func() time.Time
	// Intn returns a uniform value in [0,n); replaceable for deterministic tests.
	Intn      func(n int) int
	fwd       map[fwdKey]*entry
	rev       map[revKey]*entry
	order     *list.List // entries, oldest at the front
	nextSweep time.Time
	c         Counters
}

// New builds a NAT with Python's defaults when maxEntries/low/high are zero.
func New(external netip.Addr, maxEntries, low, high int) (*Nat, error) {
	if !external.Is4() {
		return nil, errors.New("external address must be IPv4")
	}
	if maxEntries == 0 {
		maxEntries = 32768
	}
	if low == 0 && high == 0 {
		low, high = 20000, 60999
	}
	if maxEntries < 1 || maxEntries > 1_000_000 || low < 1024 || low >= high || high > 65535 {
		return nil, errors.New("invalid NAT limits")
	}
	return &Nat{external: external.As4(), maxEntries: maxEntries, low: low, high: high, Now: time.Now,
		Intn: func(n int) int { v, _ := rand.Int(rand.Reader, big.NewInt(int64(n))); return int(v.Int64()) },
		fwd:  map[fwdKey]*entry{}, rev: map[revKey]*entry{}, order: list.New()}, nil
}

func (n *Nat) Stats() Counters {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.c
	c.Active = len(n.fwd)
	return c
}

func fold(v uint32) uint32 {
	for v>>16 != 0 {
		v = v&0xFFFF + v>>16
	}
	return v
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return ^uint16(fold(sum))
}

// adjust is the RFC 1624 incremental update for replaced 16-bit words.
func adjust(csum uint16, old, new []byte) uint16 {
	total := uint32(^csum)
	for i := 0; i < len(old); i += 2 {
		total += uint32(^(uint16(old[i])<<8 | uint16(old[i+1]))) + (uint32(new[i])<<8 | uint32(new[i+1]))
	}
	return ^uint16(fold(total))
}

func (n *Nat) parse(p []byte) (data []byte, ihl int, proto byte, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		n.c.Malformed++
		return nil, 0, 0, false
	}
	ihl = int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	if ihl < 20 || total < ihl || total > len(p) {
		n.c.Malformed++
		return nil, 0, 0, false
	}
	if binary.BigEndian.Uint16(p[6:])&0x3FFF != 0 {
		n.c.Fragments++
		return nil, 0, 0, false
	}
	return append([]byte(nil), p[:total]...), ihl, p[9], true
}

func tcpState(e *entry, flags byte) {
	if flags&0x05 != 0 {
		e.state = "closing"
	} else if e.state == "new" && flags&0x10 != 0 && flags&0x02 == 0 {
		e.state = "est"
	}
}

func (n *Nat) remove(e *entry) {
	delete(n.fwd, fwdKey{e.proto, e.intIP, e.intPort})
	delete(n.rev, revKey{e.proto, e.extPort})
	n.order.Remove(e.elem)
}

func (n *Nat) sweep(now time.Time) {
	if now.Before(n.nextSweep) {
		return
	}
	n.nextSweep = now.Add(time.Second)
	var dead []*entry
	for el := n.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*entry)
		if now.Sub(e.last) > e.timeout() {
			dead = append(dead, e)
		}
	}
	for _, e := range dead {
		n.remove(e)
		n.c.Expired++
	}
}

func (n *Nat) allocate(proto byte, preferred uint16) (uint16, bool) {
	lowest := 1024
	if proto == ICMP {
		lowest = 1
	}
	if int(preferred) >= lowest {
		if _, used := n.rev[revKey{proto, preferred}]; !used {
			return preferred, true
		}
	}
	for i := 0; i < 64; i++ {
		c := uint16(n.low + n.Intn(n.high-n.low+1))
		if _, used := n.rev[revKey{proto, c}]; !used {
			return c, true
		}
	}
	return 0, false
}

func (n *Nat) entryFor(proto byte, ip [4]byte, port uint16, now time.Time) *entry {
	key := fwdKey{proto, ip, port}
	if e, ok := n.fwd[key]; ok {
		return e
	}
	if len(n.fwd) >= n.maxEntries {
		n.remove(n.order.Front().Value.(*entry))
		n.c.Evicted++
	}
	ext, ok := n.allocate(proto, port)
	if !ok {
		return nil
	}
	e := &entry{proto: proto, intIP: ip, intPort: port, extPort: ext, remotes: map[remote]*list.Element{}, order: list.New(), last: now, state: "new"}
	e.elem = n.order.PushBack(e)
	n.fwd[key] = e
	n.rev[revKey{proto, ext}] = e
	n.c.Created++
	return e
}

func (e *entry) touchRemote(r remote) {
	if el, ok := e.remotes[r]; ok {
		e.order.MoveToBack(el)
	} else {
		e.remotes[r] = e.order.PushBack(r)
	}
	for e.order.Len() > MaxRemotes {
		front := e.order.Front()
		delete(e.remotes, front.Value.(remote))
		e.order.Remove(front)
	}
}

// Outbound rewrites the source of a local packet to the external address. A
// nil result means the packet was dropped.
func (n *Nat) Outbound(packet []byte) []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	data, ihl, proto, ok := n.parse(packet)
	if !ok {
		return nil
	}
	now := n.Now()
	n.sweep(now)
	var keyPort, remotePort uint16
	switch {
	case proto == TCP || proto == UDP:
		need := 8
		if proto == TCP {
			need = 20
		}
		if len(data) < ihl+need {
			n.c.Malformed++
			return nil
		}
		keyPort, remotePort = binary.BigEndian.Uint16(data[ihl:]), binary.BigEndian.Uint16(data[ihl+2:])
	case proto == ICMP && len(data) >= ihl+8 && data[ihl] == icmpEchoRequest:
		keyPort = binary.BigEndian.Uint16(data[ihl+4:])
	default:
		n.c.Unsupported++
		return nil
	}
	var intIP, dst [4]byte
	copy(intIP[:], data[12:16])
	copy(dst[:], data[16:20])
	e := n.entryFor(proto, intIP, keyPort, now)
	if e == nil {
		n.c.PortExhausted++
		return nil
	}
	e.touchRemote(remote{dst, remotePort})
	e.last = now
	n.order.MoveToBack(e.elem)
	if proto == TCP {
		tcpState(e, data[ihl+13])
	}
	n.rewrite(data, ihl, proto, true, n.external, e.extPort)
	n.c.Out++
	return data
}

// Inbound translates a packet addressed to the external address back to the
// internal host.
func (n *Nat) Inbound(packet []byte) []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	data, ihl, proto, ok := n.parse(packet)
	if !ok {
		return nil
	}
	if [4]byte(data[16:20]) != n.external {
		n.c.NotForUs++
		return nil
	}
	now := n.Now()
	n.sweep(now)
	var e *entry
	var r remote
	copy(r.ip[:], data[12:16])
	switch {
	case proto == TCP || proto == UDP:
		need := 8
		if proto == TCP {
			need = 20
		}
		if len(data) < ihl+need {
			n.c.Malformed++
			return nil
		}
		r.port = binary.BigEndian.Uint16(data[ihl:])
		e = n.rev[revKey{proto, binary.BigEndian.Uint16(data[ihl+2:])}]
	case proto == ICMP && len(data) >= ihl+8:
		kind := data[ihl]
		switch {
		case kind == icmpEchoReply:
			e = n.rev[revKey{ICMP, binary.BigEndian.Uint16(data[ihl+4:])}]
		case kind == 3 || kind == 4 || kind == 11 || kind == 12:
			return n.inboundError(data, ihl, now)
		default:
			n.c.Unsupported++
			return nil
		}
	default:
		n.c.Unsupported++
		return nil
	}
	if e == nil {
		n.c.NoMapping++
		return nil
	}
	if _, ok := e.remotes[r]; !ok {
		n.c.Filtered++
		return nil
	}
	e.last = now
	n.order.MoveToBack(e.elem)
	if proto == TCP {
		tcpState(e, data[ihl+13])
	}
	n.rewrite(data, ihl, proto, false, e.intIP, e.intPort)
	n.c.In++
	return data
}

func put16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }

// rewrite replaces the source (src) or destination endpoint and repairs every
// affected checksum incrementally.
func (n *Nat) rewrite(data []byte, ihl int, proto byte, src bool, ip [4]byte, port uint16) {
	off := 16
	if src {
		off = 12
	}
	oldIP := append([]byte(nil), data[off:off+4]...)
	copy(data[off:], ip[:])
	put16(data[10:], adjust(binary.BigEndian.Uint16(data[10:]), oldIP, ip[:]))
	if proto == ICMP {
		oldID := append([]byte(nil), data[ihl+4:ihl+6]...)
		var newID [2]byte
		put16(newID[:], port)
		copy(data[ihl+4:], newID[:])
		put16(data[ihl+2:], adjust(binary.BigEndian.Uint16(data[ihl+2:]), oldID, newID[:]))
		return
	}
	po := ihl + 2
	if src {
		po = ihl
	}
	oldPort := append([]byte(nil), data[po:po+2]...)
	var np [2]byte
	put16(np[:], port)
	copy(data[po:], np[:])
	co := ihl + 6
	if proto == TCP {
		co = ihl + 16
	}
	cs := binary.BigEndian.Uint16(data[co:])
	if proto == UDP && cs == 0 {
		return
	}
	cs = adjust(cs, append(append([]byte(nil), oldIP...), oldPort...), append(append([]byte(nil), ip[:]...), np[:]...))
	if cs == 0 && proto == UDP {
		cs = 0xFFFF
	}
	put16(data[co:], cs)
}

func (n *Nat) inboundError(data []byte, ihl int, now time.Time) []byte {
	n.c.ICMPErrors++
	inner := ihl + 8
	if len(data) < inner+28 || data[inner]>>4 != 4 {
		n.c.Malformed++
		return nil
	}
	innerIHL := int(data[inner]&15) * 4
	proto := data[inner+9]
	if (proto != TCP && proto != UDP) || innerIHL < 20 || len(data) < inner+innerIHL+8 {
		n.c.Unsupported++
		return nil
	}
	if [4]byte(data[inner+12:inner+16]) != n.external {
		n.c.NoMapping++
		return nil
	}
	e := n.rev[revKey{proto, binary.BigEndian.Uint16(data[inner+innerIHL:])}]
	if e == nil {
		n.c.NoMapping++
		return nil
	}
	var q remote
	copy(q.ip[:], data[inner+16:inner+20])
	q.port = binary.BigEndian.Uint16(data[inner+innerIHL+2:])
	if _, ok := e.remotes[q]; !ok {
		n.c.Filtered++
		return nil
	}
	e.last = now
	copy(data[16:20], e.intIP[:])
	put16(data[10:], 0)
	put16(data[10:], checksum(data[:ihl]))
	copy(data[inner+12:inner+16], e.intIP[:])
	put16(data[inner+innerIHL:], e.intPort)
	put16(data[inner+10:], 0)
	put16(data[inner+10:], checksum(data[inner:inner+innerIHL]))
	put16(data[ihl+2:], 0)
	put16(data[ihl+2:], checksum(data[ihl:]))
	n.c.In++
	return data
}
