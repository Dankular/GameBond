package carrier

import (
	"errors"
	"math"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// StreamEndpoint is one fallback stream endpoint.
type StreamEndpoint struct {
	Mode       string  `json:"mode"`
	Port       int     `json:"port"`
	CAFile     string  `json:"ca_file"`
	ServerName *string `json:"server_name"`
}

func (e StreamEndpoint) Validate() error {
	if !validMode(e.Mode) || e.Port < 1 || e.Port > 65535 {
		return errors.New("Invalid stream endpoint")
	}
	if e.Mode != "tcp" && e.CAFile == "" {
		return errors.New("TLS/HTTPS need a trusted CA file")
	}
	if e.ServerName != nil && (len(*e.ServerName) > 253 || containsNUL(*e.ServerName)) {
		return errors.New("Invalid TLS server name")
	}
	return nil
}

func containsNUL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return true
		}
	}
	return false
}

// Settings are the OuterSettings (python defaults: 1.5 s, 5 s, 32 packets).
type Settings struct {
	Endpoints        []StreamEndpoint `json:"endpoints"`
	FallbackAfter    float64          `json:"fallback_after"`
	RecoveryInterval float64          `json:"recovery_interval"`
	QueuePackets     int              `json:"queue_packets"`
}

// DefaultSettings returns Python's defaults for the given endpoints.
func DefaultSettings(eps ...StreamEndpoint) Settings {
	return Settings{Endpoints: eps, FallbackAfter: 1.5, RecoveryInterval: 5, QueuePackets: 32}
}

func (s Settings) Validate() error {
	if len(s.Endpoints) < 1 || len(s.Endpoints) > 3 {
		return errors.New("Configure one to three fallback endpoints")
	}
	seen := map[string]bool{}
	for _, e := range s.Endpoints {
		if err := e.Validate(); err != nil {
			return err
		}
		k := e.Mode + ":" + strconv.Itoa(e.Port)
		if seen[k] {
			return errors.New("Duplicate fallback endpoint")
		}
		seen[k] = true
	}
	for _, v := range []float64{s.FallbackAfter, s.RecoveryInterval} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < .1 || v > 300 {
			return errors.New("Invalid carrier timer")
		}
	}
	if s.QueuePackets < 1 || s.QueuePackets > 128 {
		return errors.New("Invalid carrier queue bound")
	}
	return nil
}

// Received is one packet delivered by the socket.
type Received struct {
	Packet     []byte
	Transport  string // "udp" or the stream mode
	Generation int
}

// Stats mirrors CarrierSocket.stats().
type Stats struct {
	Mode          string
	Ready         bool
	LastError     string
	PeerConfirmed bool
	QueuePackets  int
	QueueLimit    int
	Counters      map[string]int
}

// Socket is a UDP-like path that falls back to a stream carrier when no
// authenticated UDP packet has arrived for FallbackAfter seconds. Only
// NoteAuthenticated (called after packet authentication) establishes health.
type Socket struct {
	udp       *net.UDPConn
	peer      *net.UDPAddr
	key, sess []byte
	settings  Settings
	source    net.IP
	control   func(network, address string, c syscall.RawConn) error

	recv chan Received

	mu           sync.Mutex
	mode         string
	ready        bool
	conn         net.Conn
	lastErr      string
	lastUDPAuth  time.Time
	counts       map[string]int
	generation   int
	confirmedGen int
	out          *Queue
	activate     bool
	activateWake chan struct{}
	stop         chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	now          func() time.Time
}

// NewSocket takes ownership of udp (already bound/pinned) and starts workers.
// control (optional) pins the TCP fallback to the same adapter.
func NewSocket(udp *net.UDPConn, peer *net.UDPAddr, key, session []byte, settings Settings, control func(network, address string, c syscall.RawConn) error) (*Socket, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if peer == nil || peer.IP.To4() == nil {
		return nil, errors.New("carrier peer must be IPv4")
	}
	s := &Socket{udp: udp, peer: peer, key: key, sess: session, settings: settings, control: control,
		recv: make(chan Received, 256), mode: "udp", counts: map[string]int{}, confirmedGen: -1,
		out: NewQueue(settings.QueuePackets), activateWake: make(chan struct{}, 1), stop: make(chan struct{}), now: time.Now}
	if la, ok := udp.LocalAddr().(*net.UDPAddr); ok && la.IP != nil && !la.IP.IsUnspecified() {
		s.source = la.IP
	}
	s.lastUDPAuth = s.now()
	s.wg.Add(2)
	go s.udpRead()
	go s.streamLoop()
	return s, nil
}

// Recv is the delivery channel (256-deep; overflow drops are counted).
func (s *Socket) Recv() <-chan Received { return s.recv }

func (s *Socket) enqueue(r Received) {
	select {
	case <-s.stop:
		return
	default:
	}
	select {
	case s.recv <- r:
	default:
		s.mu.Lock()
		s.counts["receive_queue_drops"]++
		s.mu.Unlock()
	}
}

func (s *Socket) udpRead() {
	defer s.wg.Done()
	buf := make([]byte, MaxFrame+1)
	for {
		n, from, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if !from.IP.Equal(s.peer.IP) || from.Port != s.peer.Port {
			continue
		}
		s.enqueue(Received{Packet: append([]byte(nil), buf[:n]...), Transport: "udp"})
	}
}

// Send transmits via UDP, or queues on the stream when in fallback.
func (s *Socket) Send(packet []byte) error {
	s.mu.Lock()
	mode, ready := s.mode, s.ready
	if mode == "udp" {
		s.mu.Unlock()
		_, err := s.udp.WriteToUDP(packet, s.peer)
		return err
	}
	defer s.mu.Unlock()
	if !ready {
		return ErrWouldBlock
	}
	if len(packet) < 1 || len(packet) > MaxFrame {
		return errors.New("Carrier frame too large")
	}
	if !s.out.Put(append([]byte(nil), packet...), Urgent(packet)) {
		s.counts["send_queue_drops"]++
		return ErrWouldBlock
	}
	return nil
}

// ErrWouldBlock is Python's BlockingIOError (reconnecting or queue full).
var ErrWouldBlock = errors.New("carrier would block")

// SendUDPProbe always uses UDP, even in fallback, so recovery can be detected.
func (s *Socket) SendUDPProbe(packet []byte) error {
	_, err := s.udp.WriteToUDP(packet, s.peer)
	return err
}

// NoteAuthenticated records that r passed packet authentication.
func (s *Socket) NoteAuthenticated(r Received) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Transport == "udp" {
		s.lastUDPAuth = s.now()
	} else if r.Generation == s.generation {
		s.confirmedGen = s.generation
	}
}

// Tick requests fallback if UDP has been silent for FallbackAfter.
func (s *Socket) Tick(now time.Time) {
	s.mu.Lock()
	if now.Sub(s.lastUDPAuth).Seconds() >= s.settings.FallbackAfter {
		s.activate = true
	}
	s.mu.Unlock()
	select {
	case s.activateWake <- struct{}{}:
	default:
	}
}

// ReturnToUDP abandons the stream carrier after UDP recovers.
func (s *Socket) ReturnToUDP() {
	s.mu.Lock()
	s.lastUDPAuth = s.now()
	s.mode, s.ready, s.activate = "udp", false, false
	s.counts["udp_recoveries"]++
	conn := s.conn
	s.counts["discarded_on_transition"] += s.out.Drain()
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (s *Socket) active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activate
}

func (s *Socket) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

func (s *Socket) streamLoop() {
	defer s.wg.Done()
	backoff := 250 * time.Millisecond
	sleep := func(d time.Duration) {
		select {
		case <-s.stop:
		case <-time.After(d):
		}
	}
	for !s.stopped() {
		if !s.active() {
			select {
			case <-s.stop:
				return
			case <-s.activateWake:
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		connected := false
		for _, ep := range s.settings.Endpoints {
			if s.stopped() || !s.active() {
				break
			}
			s.mu.Lock()
			s.counts["connection_attempts"]++
			s.mu.Unlock()
			opts := DialOptions{Source: s.source, CAFile: ep.CAFile, Control: s.control}
			if ep.ServerName != nil {
				opts.ServerName = *ep.ServerName
			}
			opts.OnConn = func(c net.Conn) error {
				s.mu.Lock()
				defer s.mu.Unlock()
				if s.stopped() || !s.activate {
					return errors.New("Fallback cancelled")
				}
				s.conn = c
				return nil
			}
			conn, err := Dial(net.JoinHostPort(s.peer.IP.String(), strconv.Itoa(ep.Port)), ep.Mode, s.key, s.sess, opts)
			if err == nil {
				s.mu.Lock()
				if s.stopped() || !s.activate {
					err = errors.New("Fallback cancelled")
				} else {
					s.conn, s.mode, s.ready, s.lastErr = conn, ep.Mode, true, ""
					s.counts["connections"]++
					s.generation++
				}
				gen := s.generation
				s.mu.Unlock()
				if err == nil {
					connected, backoff = true, 250*time.Millisecond
					err = Pump(conn, s.out, func(p []byte) { s.enqueue(Received{Packet: p, Transport: ep.Mode, Generation: gen}) },
						func() bool { return s.stopped() || !s.active() }, nil,
						func(name string, n int) { s.mu.Lock(); s.counts[name] += n; s.mu.Unlock() })
				}
				conn.Close()
			}
			s.mu.Lock()
			if err != nil {
				s.lastErr = truncate(err.Error())
				s.counts["connection_errors"]++
			}
			s.ready, s.conn = false, nil
			s.counts["discarded_on_transition"] += s.out.Drain()
			s.mu.Unlock()
			if connected {
				break
			}
		}
		sleep(backoff)
		backoff = min(5*time.Second, backoff*2)
	}
}

func (s *Socket) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := make(map[string]int, len(s.counts))
	for k, v := range s.counts {
		c[k] = v
	}
	return Stats{Mode: s.mode, Ready: s.ready, LastError: s.lastErr, PeerConfirmed: s.ready && s.confirmedGen == s.generation,
		QueuePackets: s.out.Len(), QueueLimit: s.settings.QueuePackets, Counters: c}
}

func (s *Socket) Close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		s.mu.Lock()
		s.activate = false
		conn := s.conn
		s.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		s.udp.Close()
	})
	s.wg.Wait()
}
