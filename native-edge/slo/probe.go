// Package slo measures what the tunnel delivers, end to end, and judges it against objectives.
//
// The measurement is an ICMP echo sent through the tunnel to the server's tunnel address: the packet
// crosses the bonded transport, the server's TUN device and the kernel, and the reply crosses it
// back, so a probe that never returns was lost somewhere on that real path. Counters inside the
// transport cannot say that; they only see their own half.
package slo

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Sink receives probe outcomes. sent is the time the probe left; outcomes are attributed to it, so
// a loss is charged to the minute in which the packet was sent, not the minute it was given up on.
type Sink interface {
	Sent(sent time.Time)
	Received(sent time.Time, rtt time.Duration)
	// Lost reports a probe not answered within the timeout. A reply that arrives afterwards is
	// reported by Late and the probe stays lost.
	Lost(sent time.Time)
	Late(sent time.Time, rtt time.Duration)
}

// ProbeConfig describes the probe stream.
type ProbeConfig struct {
	Src, Dst netip.Addr    // tunnel addresses of the client and the server
	ID       uint16        // ICMP identifier; replies carrying another one are not ours
	Size     int           // total IP packet size, at least 40
	Timeout  time.Duration // an unanswered probe is lost after this (default 1 s)
}

type pending struct {
	seq  uint32
	sent time.Time
}

// Prober builds probes and matches replies. Build, Handle and Expire may be called from different
// goroutines.
type Prober struct {
	cfg  ProbeConfig
	sink Sink
	mu   sync.Mutex
	seq  uint32
	open map[uint32]time.Time
	fifo []pending // send order; entries already answered are skipped lazily
	lost map[uint32]time.Time
	lq   []pending
}

// NewProber returns a prober reporting to sink.
func NewProber(cfg ProbeConfig, sink Sink) *Prober {
	if cfg.Size < 40 {
		cfg.Size = 64
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Second
	}
	return &Prober{cfg: cfg, sink: sink, open: map[uint32]time.Time{}, lost: map[uint32]time.Time{}}
}

const icmpEchoRequest, icmpEchoReply = 8, 0

// Build returns the next probe packet and records it as sent at now.
func (p *Prober) Build(now time.Time) []byte {
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.open[seq] = now
	p.fifo = append(p.fifo, pending{seq, now})
	p.mu.Unlock()
	p.sink.Sent(now)

	n := p.cfg.Size
	b := make([]byte, n)
	b[0], b[8], b[9] = 0x45, 64, 1 // IPv4, ttl 64, ICMP
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	binary.BigEndian.PutUint16(b[4:], uint16(seq))
	src, dst := p.cfg.Src.As4(), p.cfg.Dst.As4()
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	b[20] = icmpEchoRequest
	binary.BigEndian.PutUint16(b[24:], p.cfg.ID)
	binary.BigEndian.PutUint16(b[26:], uint16(seq))
	binary.BigEndian.PutUint32(b[28:], seq) // the full sequence, past the 16 bits ICMP has
	binary.BigEndian.PutUint64(b[32:], uint64(now.UnixNano()))
	binary.BigEndian.PutUint16(b[22:], checksum(b[20:]))
	return b
}

// Handle consumes pkt when it is an echo reply to one of this prober's probes and reports whether it
// was. Anything else is left for the caller.
func (p *Prober) Handle(pkt []byte, now time.Time) bool {
	if len(pkt) < 36 || pkt[0]>>4 != 4 || pkt[9] != 1 {
		return false
	}
	ihl := int(pkt[0]&15) * 4
	if ihl != 20 || len(pkt) < ihl+16 || pkt[ihl] != icmpEchoReply || binary.BigEndian.Uint16(pkt[ihl+4:]) != p.cfg.ID {
		return false
	}
	if netip.AddrFrom4([4]byte(pkt[12:16])) != p.cfg.Dst || netip.AddrFrom4([4]byte(pkt[16:20])) != p.cfg.Src {
		return false
	}
	seq := binary.BigEndian.Uint32(pkt[ihl+8:])
	p.mu.Lock()
	if sent, ok := p.open[seq]; ok {
		delete(p.open, seq)
		p.mu.Unlock()
		p.sink.Received(sent, now.Sub(sent))
		return true
	}
	sent, late := p.lost[seq]
	delete(p.lost, seq)
	p.mu.Unlock()
	if late {
		p.sink.Late(sent, now.Sub(sent))
	}
	return true // ours, a duplicate or very late: still not for the stack
}

// Expire gives up on probes older than the timeout and forgets lost ones after ten timeouts.
func (p *Prober) Expire(now time.Time) {
	p.mu.Lock()
	var gone []time.Time
	for len(p.fifo) > 0 {
		e := p.fifo[0]
		sent, still := p.open[e.seq]
		if still && now.Sub(e.sent) < p.cfg.Timeout {
			break
		}
		p.fifo = p.fifo[1:]
		if still && sent.Equal(e.sent) {
			delete(p.open, e.seq)
			p.lost[e.seq] = e.sent
			p.lq = append(p.lq, pending{e.seq, e.sent})
			gone = append(gone, e.sent)
		}
	}
	for len(p.lq) > 0 && now.Sub(p.lq[0].sent) > 10*p.cfg.Timeout {
		delete(p.lost, p.lq[0].seq)
		p.lq = p.lq[1:]
	}
	if len(p.fifo) == 0 {
		p.fifo = nil
	}
	p.mu.Unlock()
	for _, s := range gone {
		p.sink.Lost(s)
	}
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// Reply turns an echo request into the reply a kernel would send. Tests and the loopback server
// stand-in use it.
func Reply(req []byte) []byte {
	if len(req) < 28 || req[20] != icmpEchoRequest {
		return nil
	}
	r := append([]byte(nil), req...)
	copy(r[12:16], req[16:20])
	copy(r[16:20], req[12:16])
	r[10], r[11] = 0, 0
	binary.BigEndian.PutUint16(r[10:], checksum(r[:20]))
	r[20] = icmpEchoReply
	r[22], r[23] = 0, 0
	binary.BigEndian.PutUint16(r[22:], checksum(r[20:]))
	return r
}
