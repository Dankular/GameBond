package dns

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Stats are the Python responder counters.
type Stats struct {
	Queries, Overrides, Forwarded, Malformed, RefusedSources, Busy, UpstreamErrors uint64
}

// Responder answers UDP and TCP queries on cfg.Bind.
type Responder struct {
	cfg   *Config
	udp   *net.UDPConn
	tcp   *net.TCPListener
	slots chan struct{}
	wg    sync.WaitGroup
	done  chan struct{}
	once  sync.Once
	c     struct{ q, o, f, m, r, b, u atomic.Uint64 }
}

func sourceIsLocal(a, bind netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a == bind
}

// NewResponder builds a responder without sockets (for Answer).
func NewResponder(cfg *Config) *Responder {
	return &Responder{cfg: cfg, slots: make(chan struct{}, cfg.Workers+cfg.Pending), done: make(chan struct{})}
}

// Answer builds the reply for one query.
func (r *Responder) Answer(packet []byte, tcp bool) []byte {
	r.c.q.Add(1)
	q, err := ParseQuestion(packet, false)
	if err != nil {
		r.c.m.Add(1)
		return response(packet, nil, 1, false, nil, 0, false)
	}
	if q.Class != 1 {
		return response(packet, &q, 5, false, nil, 0, false)
	}
	if rec, ok := r.cfg.Records[q.Name()]; ok {
		r.c.o.Add(1)
		return response(packet, &q, 0, true, r.cfg.answers(rec, q.Kind), r.cfg.TTL, tcp)
	}
	if r.cfg.Upstream == nil {
		return response(packet, &q, 5, false, nil, 0, false)
	}
	tx := make([]byte, 2)
	_, _ = rand.Read(tx)
	res, err := r.exchange(append(tx, packet[2:]...), tcp)
	if err == nil {
		var rq Question
		if rq, err = ParseQuestion(res, true); err == nil {
			if res[0] != tx[0] || res[1] != tx[1] || rq.Name() != q.Name() || rq.Kind != q.Kind || rq.Class != q.Class {
				err = fe("upstream DNS response does not match the query")
			}
		}
	}
	if err != nil {
		r.c.u.Add(1)
		return response(packet, &q, 2, false, nil, 0, false)
	}
	r.c.f.Add(1)
	return append(append([]byte{}, packet[:2]...), res[2:]...)
}

func (r *Responder) exchange(packet []byte, tcp bool) ([]byte, error) {
	d := net.Dialer{Timeout: r.cfg.Timeout}
	network := "udp4"
	if tcp {
		network = "tcp4"
		d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(r.cfg.Bind.Addr(), 0))
	} else {
		d.LocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(r.cfg.Bind.Addr(), 0))
	}
	conn, err := d.Dial(network, r.cfg.Upstream.String()) // bound to the tunnel address
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(r.cfg.Timeout))
	if !tcp {
		if _, err = conn.Write(packet); err != nil {
			return nil, err
		}
		buf := make([]byte, MaxResponse)
		n, err := conn.Read(buf)
		return buf[:n], err
	}
	if _, err = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err = io.ReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < 12 {
		return nil, fe("invalid upstream TCP DNS length")
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(conn, buf)
	return buf, err
}

// Start binds UDP and TCP on the same address and serves until Close.
func Start(cfg *Config) (*Responder, error) {
	if !cfg.Enabled {
		return nil, errors.New("DNS profile is disabled")
	}
	r := NewResponder(cfg)
	var err error
	attempts := 1
	if cfg.Bind.Port() == 0 {
		attempts = 1024 // Windows hands out TCP ports sequentially, so a UDP-excluded range can be hundreds wide
	}
	for i := 0; i < attempts; i++ {
		r.tcp, err = net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(cfg.Bind))
		if err != nil {
			continue
		}
		addr := r.tcp.Addr().(*net.TCPAddr)
		r.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: addr.IP, Port: addr.Port})
		if err == nil {
			break
		}
		r.tcp.Close()
	}
	if err != nil {
		return nil, err
	}
	r.wg.Add(2)
	go r.serveUDP()
	go r.serveTCP()
	return r, nil
}

func (r *Responder) Addr() netip.AddrPort { return r.tcp.Addr().(*net.TCPAddr).AddrPort() }

func (r *Responder) Stats() Stats {
	return Stats{r.c.q.Load(), r.c.o.Load(), r.c.f.Load(), r.c.m.Load(), r.c.r.Load(), r.c.b.Load(), r.c.u.Load()}
}

func (r *Responder) admit() bool {
	select {
	case r.slots <- struct{}{}:
		return true
	default:
		r.c.b.Add(1)
		return false
	}
}

func (r *Responder) closed() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

func (r *Responder) serveUDP() {
	defer r.wg.Done()
	buf := make([]byte, MaxQuery+1)
	for {
		n, src, err := r.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if r.closed() {
				return
			}
			continue
		}
		if !sourceIsLocal(src.Addr(), r.cfg.Bind.Addr()) {
			r.c.r.Add(1)
			continue
		}
		pkt := append([]byte{}, buf[:n]...)
		if !r.admit() {
			_, _ = r.udp.WriteToUDPAddrPort(response(pkt, nil, 2, false, nil, 0, false), src)
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { <-r.slots }()
			_, _ = r.udp.WriteToUDPAddrPort(r.Answer(pkt, false), src)
		}()
	}
}

func (r *Responder) serveTCP() {
	defer r.wg.Done()
	for {
		c, err := r.tcp.AcceptTCP()
		if err != nil {
			if r.closed() {
				return
			}
			continue
		}
		if !sourceIsLocal(c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr(), r.cfg.Bind.Addr()) {
			r.c.r.Add(1)
			c.Close()
			continue
		}
		if !r.admit() {
			c.Close()
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { <-r.slots }()
			defer c.Close()
			deadline := time.Now().Add(r.cfg.Timeout * 2)
			_ = c.SetDeadline(deadline)
			for i := 0; i < 16 && time.Now().Before(deadline); i++ {
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(lb[:]))
				if n < 12 || n > MaxQuery {
					return
				}
				pkt := make([]byte, n)
				if _, err := io.ReadFull(c, pkt); err != nil {
					return
				}
				out := r.Answer(pkt, true)
				if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...)); err != nil {
					return
				}
			}
		}()
	}
}

// Close stops the listeners and waits for in-flight queries.
func (r *Responder) Close() {
	r.once.Do(func() {
		close(r.done)
		r.udp.Close()
		r.tcp.Close()
		r.wg.Wait()
	})
}
