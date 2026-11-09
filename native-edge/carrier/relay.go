package carrier

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// Queue is a bounded two-priority packet queue (urgent before bulk, FIFO within).
type Queue struct {
	mu     sync.Mutex
	limit  int
	urgent [][]byte
	bulk   [][]byte
	wake   chan struct{}
}

func NewQueue(limit int) *Queue { return &Queue{limit: limit, wake: make(chan struct{}, 1)} }

// Put enqueues; false means the queue was full.
func (q *Queue) Put(packet []byte, urgent bool) bool {
	q.mu.Lock()
	if len(q.urgent)+len(q.bulk) >= q.limit {
		q.mu.Unlock()
		return false
	}
	if urgent {
		q.urgent = append(q.urgent, packet)
	} else {
		q.bulk = append(q.bulk, packet)
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// Get pops the next packet without blocking.
func (q *Queue) Get() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch {
	case len(q.urgent) > 0:
		p := q.urgent[0]
		q.urgent = q.urgent[1:]
		return p, true
	case len(q.bulk) > 0:
		p := q.bulk[0]
		q.bulk = q.bulk[1:]
		return p, true
	}
	return nil, false
}

func (q *Queue) Len() int { q.mu.Lock(); defer q.mu.Unlock(); return len(q.urgent) + len(q.bulk) }

// Drain discards everything and returns how many packets were dropped.
func (q *Queue) Drain() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := len(q.urgent) + len(q.bulk)
	q.urgent, q.bulk = nil, nil
	return n
}

// Wake signals that a packet may be available.
func (q *Queue) Wake() <-chan struct{} { return q.wake }

// Pump moves frames both ways until stopped or an error: it writes queued
// packets to conn and hands received frames to onPacket. If upstream is set
// (relay side) datagrams read from it are queued for the stream. Idle for 30 s
// is an error, as in Python.
func Pump(conn net.Conn, out *Queue, onPacket func([]byte), stopped func() bool, upstream net.Conn, count func(name string, n int)) error {
	if count == nil {
		count = func(string, int) {}
	}
	errc := make(chan error, 3)
	done := make(chan struct{})
	defer close(done)
	// reader
	go func() {
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			packet, err := ReadFrame(conn)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					err = errors.New("Carrier idle timeout")
				}
				errc <- err
				return
			}
			count("rx_framed_bytes", len(packet)+2)
			onPacket(packet)
		}
	}()
	// upstream UDP -> queue
	if upstream != nil {
		go func() {
			buf := make([]byte, MaxFrame+1)
			for {
				upstream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, err := upstream.Read(buf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						select {
						case <-done:
							return
						default:
							continue
						}
					}
					select {
					case <-done:
					default:
						errc <- err
					}
					return
				}
				if n > MaxFrame {
					errc <- errors.New("Carrier datagram exceeds its bound")
					return
				}
				p := append([]byte(nil), buf[:n]...)
				if !out.Put(p, Urgent(p)) {
					count("send_queue_drops", 1)
				}
			}
		}()
	}
	// writer loop on this goroutine
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if stopped() {
			return nil
		}
		for {
			p, ok := out.Get()
			if !ok {
				break
			}
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := WriteFrame(conn, p); err != nil {
				return err
			}
			count("tx_framed_bytes", len(p)+2)
		}
		select {
		case err := <-errc:
			return err
		case <-out.Wake():
		case <-tick.C:
		}
	}
}

// RelayConfig configures a fixed-destination relay.
type RelayConfig struct {
	Bind       string // host:port
	UDPPeer    string // host:port
	Key        []byte
	Session    []byte
	Mode       string
	TLS        *tls.Config // required unless Mode == "tcp"
	MaxClients int
}

// Relay authenticates before allocating any UDP socket.
type Relay struct {
	cfg      RelayConfig
	ln       net.Listener
	slots    chan struct{}
	mu       sync.Mutex
	counts   map[string]int
	conns    map[net.Conn]struct{}
	lastErr  string
	stopped  chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewRelay listens and starts accepting.
func NewRelay(cfg RelayConfig) (*Relay, error) {
	if !validMode(cfg.Mode) || (cfg.Mode != "tcp" && cfg.TLS == nil) {
		return nil, errors.New("Invalid relay transport")
	}
	if cfg.MaxClients < 1 || cfg.MaxClients > 32 {
		return nil, errors.New("Carrier client limit must be 1..32")
	}
	if len(cfg.Key) != 32 || len(cfg.Session) != 16 {
		return nil, errors.New("Invalid carrier key or session")
	}
	ln, err := net.Listen("tcp4", cfg.Bind)
	if err != nil {
		return nil, err
	}
	if cfg.TLS != nil {
		c := cfg.TLS.Clone()
		c.NextProtos = []string{"gamebond/1", "http/1.1"}
		if c.MinVersion < tls.VersionTLS12 {
			c.MinVersion = tls.VersionTLS12
		}
		cfg.TLS = c
	}
	r := &Relay{cfg: cfg, ln: ln, slots: make(chan struct{}, cfg.MaxClients), counts: map[string]int{}, conns: map[net.Conn]struct{}{}, stopped: make(chan struct{})}
	r.wg.Add(1)
	go r.accept()
	return r, nil
}

func (r *Relay) Addr() net.Addr { return r.ln.Addr() }

func (r *Relay) isStopped() bool {
	select {
	case <-r.stopped:
		return true
	default:
		return false
	}
}

func (r *Relay) accept() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		select {
		case r.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		r.mu.Lock()
		r.conns[c] = struct{}{}
		r.mu.Unlock()
		r.wg.Add(1)
		go r.serve(c)
	}
}

func (r *Relay) serve(orig net.Conn) {
	conn := orig
	var upstream net.Conn
	defer r.wg.Done()
	defer func() {
		conn.Close()
		orig.Close()
		if upstream != nil {
			upstream.Close()
		}
		r.mu.Lock()
		delete(r.conns, orig)
		delete(r.conns, conn)
		r.mu.Unlock()
		<-r.slots
	}()
	fail := func(err error) {
		r.mu.Lock()
		r.counts["rejected_or_closed"]++
		r.lastErr = truncate(err.Error())
		r.mu.Unlock()
	}
	deadline := time.Now().Add(3 * time.Second)
	if tc, ok := orig.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetWriteBuffer(16384)
	}
	mode := r.cfg.Mode
	if r.cfg.TLS != nil {
		t := tls.Server(orig, r.cfg.TLS)
		orig.SetDeadline(deadline)
		if err := t.Handshake(); err != nil {
			fail(err)
			return
		}
		conn = t
		r.mu.Lock()
		r.conns[conn] = struct{}{}
		r.mu.Unlock()
		mode = "tls"
		if t.ConnectionState().NegotiatedProtocol == "http/1.1" {
			mode = "https"
		}
	}
	if mode == "https" {
		h, err := readHeader(conn, deadline)
		if err != nil {
			fail(err)
			return
		}
		lines := strings.Split(string(h), "\r\n")
		bad := lines[0] != "CONNECT "+Authority+" HTTP/1.1"
		for _, l := range lines[1:] {
			if ll := strings.ToLower(l); strings.HasPrefix(ll, "content-length:") || strings.HasPrefix(ll, "transfer-encoding:") {
				bad = true
			}
		}
		if bad {
			fail(errors.New("Only the fixed GameBond CONNECT destination is accepted"))
			return
		}
		conn.SetWriteDeadline(deadline)
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			fail(err)
			return
		}
	}
	if err := Authenticate(conn, r.cfg.Key, r.cfg.Session, mode, true, deadline); err != nil {
		fail(err)
		return
	}
	r.mu.Lock()
	r.counts["authenticated"]++
	r.mu.Unlock()
	var err error
	upstream, err = net.Dial("udp4", r.cfg.UDPPeer)
	if err != nil {
		fail(err)
		return
	}
	consume := func(p []byte) {
		if _, err := upstream.Write(p); err != nil {
			r.mu.Lock()
			r.counts["up_datagram_drops"]++
			r.mu.Unlock()
			return
		}
		r.mu.Lock()
		r.counts["up_datagrams"]++
		r.mu.Unlock()
	}
	count := func(name string, n int) {
		switch name {
		case "rx_framed_bytes":
			name = "up_framed_bytes"
		case "tx_framed_bytes":
			name = "down_framed_bytes"
		}
		r.mu.Lock()
		r.counts[name] += n
		r.mu.Unlock()
	}
	if err := Pump(conn, NewQueue(32), consume, r.isStopped, upstream, count); err != nil {
		fail(err)
	}
}

func truncate(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

// Stats returns counters plus active_connections and last_error.
func (r *Relay) Stats() (map[string]int, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int{"active_connections": len(r.conns)}
	for k, v := range r.counts {
		out[k] = v
	}
	return out, r.lastErr
}

func (r *Relay) Close() {
	r.stopOnce.Do(func() {
		close(r.stopped)
		r.ln.Close()
		r.mu.Lock()
		for c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
	})
	r.wg.Wait()
}
