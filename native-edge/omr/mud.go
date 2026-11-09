package omr

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
)

// This file is gamebond/omr_glorytun.py: the client side of the Glorytun UDP
// ("mud") bonding protocol used by OpenMPTCProuter servers. It carries raw IP
// packets, aggregates several local source addresses to one server and stripes
// per packet by configured rate. Like the original it has no sequence numbers
// and no reordering and cannot replicate packets. ChaCha20-Poly1305 only
// (what OMR runs), IPv4 only.
//
// STATUS: the Python it is ported from was written from the glorytun sources
// and never exercised against a real glorytun binary, so this port is
// vector-equal to Python, not proven interoperable with a real OMR server.

const (
	TimeSize   = 6
	KeySize    = 32
	MacSize    = 16
	PktMin     = TimeSize + MacSize
	PktMax     = 1500
	MtuMin     = 576 + PktMin
	MtuMax     = 1450 + PktMin
	MsgSize    = 125
	MsgSentMax = 5
	OneMsec    = int64(1000)
	OneSec     = int64(1_000_000)
	OneMin     = 60 * OneSec
	TimeMask   = int64(1)<<(TimeSize*8) - 2
	Keepalive  = 25 * OneSec
	TimeTol    = 10 * OneMin
	KxTimeout  = 60 * OneMin
	Demotion   = 2
)

// Path status (mud.h).
const (
	Deleting = iota
	Probing
	Degraded
	Lossy
	Waiting
	Ready
	Running
)

var rolePref = map[string]int{"primary": 1, "secondary": 1, "backup": 125}

func tmask(v int64) int64 { return v & TimeMask }

// ParseKey reads a Glorytun keyfile: 64 hex characters.
func ParseKey(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if len(text) != 64 {
		return nil, errors.New("Glorytun key must be 64 hexadecimal characters")
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		for _, c := range []byte{text[2*i], text[2*i+1]} {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			default:
				return nil, errors.New("Glorytun key must be 64 hexadecimal characters")
			}
		}
		out[i] = b
	}
	return out, nil
}

func store(v int64, size int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b[:size]
}

func load(b []byte) int64 {
	var buf [8]byte
	copy(buf[:], b)
	return int64(binary.LittleEndian.Uint64(buf[:]))
}

// --- crypto -------------------------------------------------------------------

// aeadParts returns the cipher positioned after the Poly1305 key block. This
// is libsodium's original (64-bit nonce) chacha20poly1305, not the IETF one:
// the MAC covers ad || le64(len ad) || ct || le64(len ct) with no padding.
func aeadCipher(key, nonce8 []byte) (*chacha20.Cipher, [32]byte) {
	nonce12 := make([]byte, 12)
	copy(nonce12[4:], nonce8)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce12)
	if err != nil {
		panic(err)
	}
	var block [64]byte
	c.XORKeyStream(block[:], block[:])
	var pk [32]byte
	copy(pk[:], block[:32])
	return c, pk
}

func mac(pk *[32]byte, ad, ct []byte) []byte {
	m := poly1305.New(pk)
	m.Write(ad)
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(ad)))
	m.Write(l[:])
	m.Write(ct)
	binary.LittleEndian.PutUint64(l[:], uint64(len(ct)))
	m.Write(l[:])
	return m.Sum(nil)
}

// Seal builds [6B time][ciphertext][16B tag]; the time is both the AAD and the
// zero-padded 8-byte nonce.
func Seal(key, header, plain []byte) []byte {
	nonce := append(append([]byte{}, header...), 0, 0)
	c, pk := aeadCipher(key, nonce)
	out := make([]byte, len(header)+len(plain), len(header)+len(plain)+MacSize)
	copy(out, header)
	c.XORKeyStream(out[len(header):], plain)
	return append(out, mac(&pk, header, out[len(header):])...)
}

// Unseal returns nil on authentication failure.
func Unseal(key, packet []byte) []byte {
	if len(packet) < TimeSize+MacSize {
		return nil
	}
	header := packet[:TimeSize]
	body := packet[TimeSize : len(packet)-MacSize]
	tag := packet[len(packet)-MacSize:]
	nonce := append(append([]byte{}, header...), 0, 0)
	c, pk := aeadCipher(key, nonce)
	if subtle.ConstantTimeCompare(mac(&pk, header, body), tag) != 1 {
		return nil
	}
	out := make([]byte, len(body))
	c.XORKeyStream(out, body)
	return out
}

func hashKey(private, secret, pk0, pk1 []byte) []byte {
	h, err := blake2b.New(KeySize, private)
	if err != nil {
		panic(err)
	}
	h.Write(secret)
	h.Write(pk0)
	h.Write(pk1)
	return h.Sum(nil)
}

type keyPair struct{ enc, dec []byte }

// keyExchange is mud_keyx: the pre-shared key plus rotating X25519 session keys.
type keyExchange struct {
	private             keyPair
	current, next, last keyPair
	secret, local       []byte
	remote              []byte
	time                int64
	useNext             bool
	random              func(n int) []byte
}

var testPoint = []byte{0x9b, 0xf4, 0x14, 0x90, 0x0f, 0xef, 0xf8, 0x2d, 0x11, 0x32, 0x6e, 0x3d, 0x99, 0xce, 0x96, 0xb9, 0x4f, 0x79, 0x31, 0x01, 0xab, 0xaf, 0xe3, 0x03, 0x59, 0x1a, 0xcd, 0xdd, 0xb0, 0xfb, 0xe3, 0x49}

func newKeyExchange(private []byte, random func(int) []byte) *keyExchange {
	p := keyPair{private, private}
	return &keyExchange{private: p, current: p, next: p, last: p, remote: make([]byte, KeySize), random: random}
}

func (k *keyExchange) rotateIfDue(now, timeout int64) bool {
	if k.time != 0 && tmask(now-k.time) < timeout {
		return false
	}
	for {
		secret := k.random(KeySize)
		local, err := curve25519.X25519(secret, curve25519.Basepoint)
		if err != nil {
			continue
		}
		// The original rejects a keypair whose product with a fixed test point is all zero.
		if _, err := curve25519.X25519(testPoint, local); err != nil {
			continue
		}
		k.secret, k.local, k.time = secret, local, now
		return true
	}
}

func (k *keyExchange) derive(remote []byte) bool {
	if k.secret == nil {
		return false
	}
	shared, err := curve25519.X25519(k.secret, remote)
	if err != nil {
		return false
	}
	key := k.private.enc
	k.next = keyPair{hashKey(key, shared, remote, k.local), hashKey(key, shared, k.local, remote)}
	k.remote = append([]byte(nil), remote...)
	return true
}

func (k *keyExchange) encrypt(now int64, plain []byte) []byte {
	keys := k.current
	if k.useNext {
		keys = k.next
	}
	return Seal(keys.enc, store(now, TimeSize), plain)
}

func (k *keyExchange) decrypt(packet []byte) []byte {
	if p := Unseal(k.current.dec, packet); p != nil {
		return p
	}
	if p := Unseal(k.next.dec, packet); p != nil {
		k.last, k.current, k.useNext = k.current, k.next, false
		return p
	}
	if p := Unseal(k.last.dec, packet); len(p) > 0 { // Python's `or` treats b"" as a miss
		return p
	}
	return Unseal(k.private.dec, packet)
}

// --- control message (struct mud_msg, 125 bytes, little endian) ---------------

// Msg is the control message.
type Msg struct {
	SentTime         int64
	Aes              byte
	PKey             []byte
	TxBytes, TxTotal int64
	RxBytes, RxTotal int64
	FwBytes, FwTotal int64
	MaxRate          int64
	Beat             int64
	MTU              int64
	Pref, Loss       byte
	FixedRate        byte
	LossLimit        byte
	Addr             netip.AddrPort
}

func (m *Msg) Pack() []byte {
	out := make([]byte, 0, MsgSize)
	out = append(out, store(m.SentTime, 6)...)
	out = append(out, m.Aes)
	pk := m.PKey
	if pk == nil {
		pk = make([]byte, KeySize)
	}
	out = append(out, pk...)
	for _, v := range []int64{m.TxBytes, m.TxTotal, m.RxBytes, m.RxTotal, m.FwBytes, m.FwTotal, m.MaxRate} {
		out = append(out, store(v, 8)...)
	}
	out = append(out, store(m.Beat, 6)...)
	out = append(out, store(m.MTU, 2)...)
	out = append(out, m.Pref, m.Loss, m.FixedRate, m.LossLimit)
	out = append(out, make([]byte, 10)...)
	out = append(out, 0xff, 0xff)
	a := m.Addr.Addr()
	if !a.IsValid() {
		a = netip.AddrFrom4([4]byte{})
	}
	a4 := a.As4()
	out = append(out, a4[:]...)
	out = append(out, byte(m.Addr.Port()>>8), byte(m.Addr.Port()))
	return out
}

// UnpackMsg parses a control message.
func UnpackMsg(raw []byte) (*Msg, error) {
	if len(raw) < MsgSize {
		return nil, errors.New("short control message")
	}
	var a4 [4]byte
	copy(a4[:], raw[119:123])
	return &Msg{
		SentTime: load(raw[0:6]), Aes: raw[6], PKey: append([]byte(nil), raw[7:39]...),
		TxBytes: load(raw[39:47]), TxTotal: load(raw[47:55]), RxBytes: load(raw[55:63]), RxTotal: load(raw[63:71]),
		FwBytes: load(raw[71:79]), FwTotal: load(raw[79:87]), MaxRate: load(raw[87:95]), Beat: load(raw[95:101]), MTU: load(raw[101:103]),
		Pref: raw[103], Loss: raw[104], FixedRate: raw[105], LossLimit: raw[106],
		Addr: netip.AddrPortFrom(netip.AddrFrom4(a4), binary.BigEndian.Uint16(raw[123:125])),
	}, nil
}

// --- per-path state -----------------------------------------------------------

type stat struct {
	val, vr int64
	setup   bool
}

func (s *stat) update(v int64) {
	if s.setup {
		s.vr = ((s.vr << 1) + s.vr + abs64(s.val-v)) >> 2
		s.val = ((s.val << 3) - s.val + v) >> 3
	} else {
		s.setup, s.vr, s.val = true, v>>1, v
	}
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

type dir struct{ total, bytes, time, rate, loss int64 }

type msgState struct {
	time, sent       int64
	set              bool
	txTime, rxTime   int64
	txBytes, rxBytes int64
	txTotal, rxTotal int64
	txAcc, rxAcc     int64
}

// path is one local source address talking to the server.
type path struct {
	localIP                  string
	conn                     *net.UDPConn
	write                    func(wire []byte) error // overridable for tests
	hasSock                  bool
	remote                   netip.AddrPort
	txMaxRate, rxMaxRate     int64
	pref                     int
	beat                     int64
	fixedRate                int64
	lossLimit                int64
	status                   int
	idle                     int64
	tx, rx                   dir
	rtt                      stat
	msg                      msgState
	mtuMin, mtuMax           int64
	mtuProbe, mtuLast, mtuOK int64
	slot                     int
	index                    int
	enabled                  bool
	role                     string
	basePref                 int
	demoted                  bool
	badSince, goodSince      float64
	bad                      bool
	baseRTT                  float64
	baseRTTSet               bool
	reason                   string
	dataTx                   int64
}

func (p *path) updateMTU(size int64) {
	if p.mtuProbe == 0 {
		if p.mtuLast == 0 {
			p.mtuMin, p.mtuMax, p.mtuProbe = MtuMin, MtuMax, MtuMax
		}
		return
	}
	if size != 0 {
		if p.mtuMin > size || p.mtuMax < size {
			return
		}
		p.mtuMin, p.mtuLast = size+1, size
	} else {
		p.mtuMax = p.mtuProbe - 1
	}
	if p.mtuMin > p.mtuMax {
		p.mtuProbe = 0
	} else {
		p.mtuProbe = (p.mtuMin + p.mtuMax) >> 1
	}
}

// Config configures a Client.
type Config struct {
	Key               []byte
	Server            netip.AddrPort
	LocalIPs          []string
	RateMbps          float64 // 0 = 100
	Prefs             []int   // nil = from roles
	BeatMS            int     // 0 = 100
	IfaceIndices      []int
	Available         []bool
	Roles             []string
	JitterThresholdMS float64 // 0 = 8
	DemoteAfter       float64 // 0 = 0.3 s
	RecoverySeconds   float64 // 0 = 3 s

	// Open creates a path socket (default: bound to LocalIP and pinned by
	// interface index through package uplink). Nil in tests that inject writers.
	Open func(localIP string, index int) (*net.UDPConn, error)
	// Now is Unix microseconds (bit 0 is masked off); Mono is monotonic seconds.
	Now  func() int64
	Mono func() float64
	// Random supplies key-exchange entropy (default crypto/rand).
	Random func(n int) []byte
}

// Client is one Glorytun UDP session from several local addresses to one server.
type Client struct {
	mu          sync.Mutex
	cfg         Config
	paths       []*path
	kx          *keyExchange
	inbox       chan []byte
	pref        int
	rate        int64
	mtu         int64
	window      int64
	windowTime  int64
	beat        int64
	rateBps     int64
	jitterMS    float64
	demoteAfter float64
	recoverySec float64
	lastAssess  float64
	lastRecv    int64
	errors      map[string]int
	now         func() int64
	mono        func() float64

	stop    chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
	started bool
}

func (c *Client) clockNow() int64 { return tmask(c.now()) }

// NewClient validates the config and creates the path sockets.
func NewClient(cfg Config) (*Client, error) {
	if len(cfg.Key) != KeySize || len(cfg.LocalIPs) == 0 {
		return nil, errors.New("a 32-byte key and at least one local address are required")
	}
	n := len(cfg.LocalIPs)
	for name, l := range map[string]int{"interface_indices": len(cfg.IfaceIndices), "available": len(cfg.Available), "roles": len(cfg.Roles), "prefs": len(cfg.Prefs)} {
		if l != 0 && l != n {
			return nil, fmt.Errorf("%s must have one entry per local address", name)
		}
	}
	if cfg.RateMbps == 0 {
		cfg.RateMbps = 100
	}
	if cfg.BeatMS == 0 {
		cfg.BeatMS = 100
	}
	c := &Client{cfg: cfg, inbox: make(chan []byte, 4096), stop: make(chan struct{}), errors: map[string]int{"decrypt": 0, "clocksync": 0, "keyx": 0, "malformed": 0, "dropped_window": 0, "no_path": 0}}
	c.now, c.mono = cfg.Now, cfg.Mono
	if c.now == nil {
		start := time.Now()
		base := start.UnixMicro()
		c.now = func() int64 { return base + time.Since(start).Microseconds() }
	}
	if c.mono == nil {
		start := time.Now()
		c.mono = func() float64 { return time.Since(start).Seconds() }
	}
	random := cfg.Random
	if random == nil {
		random = func(n int) []byte {
			b := make([]byte, n)
			if _, err := rand.Read(b); err != nil {
				panic(err)
			}
			return b
		}
	}
	c.kx = newKeyExchange(cfg.Key, random)
	c.windowTime = c.clockNow()
	c.beat = int64(cfg.BeatMS) * OneMsec
	c.rateBps = int64(cfg.RateMbps * 1_000_000 / 8)
	c.jitterMS, c.demoteAfter, c.recoverySec = cfg.JitterThresholdMS, cfg.DemoteAfter, cfg.RecoverySeconds
	if c.jitterMS == 0 {
		c.jitterMS = 8
	}
	if c.demoteAfter == 0 {
		c.demoteAfter = .3
	}
	if c.recoverySec == 0 {
		c.recoverySec = 3
	}
	for slot, ip := range cfg.LocalIPs {
		up := true
		if cfg.Available != nil {
			up = cfg.Available[slot]
		}
		role := "primary"
		if cfg.Roles != nil {
			role = cfg.Roles[slot]
		}
		if _, ok := rolePref[role]; !ok && role != "never" {
			c.Close()
			return nil, errors.New("unknown link role " + role)
		}
		idx := 0
		if cfg.IfaceIndices != nil {
			idx = cfg.IfaceIndices[slot]
		}
		pref := -1
		if cfg.Prefs != nil {
			pref = cfg.Prefs[slot]
		}
		c.paths = append(c.paths, c.newPath(slot, ip, idx, up, role, pref))
	}
	return c, nil
}

func (c *Client) newPath(slot int, ip string, index int, up bool, role string, pref int) *path {
	enabled := up && role != "never" && ip != "" && ip != "0.0.0.0"
	reason := ""
	if !enabled {
		reason = "adapter unavailable"
		if role == "never" {
			reason = "role never"
		}
	}
	var conn *net.UDPConn
	if enabled && c.cfg.Open != nil {
		var err error
		if conn, err = c.cfg.Open(ip, index); err != nil {
			conn, enabled, reason = nil, false, err.Error()
		}
	}
	base := pref
	if base < 0 {
		base = rolePrefOr(role, 1)
	}
	p := &path{localIP: ip, conn: conn, hasSock: conn != nil, remote: c.cfg.Server, txMaxRate: c.rateBps, rxMaxRate: c.rateBps, pref: base, beat: c.beat,
		fixedRate: 1, lossLimit: 255, status: Probing, idle: c.clockNow(), slot: slot, index: index, enabled: enabled, role: role, basePref: base, reason: reason}
	p.tx.rate = c.rateBps
	return p
}

func rolePrefOr(role string, def int) int {
	if v, ok := rolePref[role]; ok {
		return v
	}
	return def
}

func (c *Client) sendPath(p *path, now int64, wire []byte) {
	if p.write != nil {
		p.write(wire)
	} else if p.conn != nil {
		p.conn.WriteToUDPAddrPort(wire, p.remote)
	}
	p.tx.total++
	p.tx.bytes += int64(len(wire))
	p.tx.time = now
	if c.window > int64(len(wire)) {
		c.window -= int64(len(wire))
	} else {
		c.window = 0
	}
}

// --- lifecycle ----------------------------------------------------------------

// Start launches the reader and timer goroutines.
func (c *Client) Start() *Client {
	c.mu.Lock()
	c.kx.rotateIfDue(c.clockNow(), KxTimeout)
	c.started = true
	c.mu.Unlock()
	for _, p := range c.paths {
		if p.conn != nil {
			c.wg.Add(1)
			go c.reader(p)
		}
	}
	c.wg.Add(1)
	go c.timer()
	return c
}

func (c *Client) reader(p *path) {
	defer c.wg.Done()
	buf := make([]byte, PktMax+1)
	for {
		n, from, err := p.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-c.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n > PktMax {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		c.mu.Lock()
		if c.paths[p.slot] == p { // a rebound slot's old socket may still hold a datagram
			c.onPacket(p, from, pkt)
		}
		c.mu.Unlock()
	}
}

func (c *Client) timer() {
	defer c.wg.Done()
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.mu.Lock()
			c.update()
			c.mu.Unlock()
		}
	}
}

// Close stops the workers and closes the sockets.
func (c *Client) Close() {
	c.stopped.Do(func() {
		close(c.stop)
		for _, p := range c.paths {
			if p.conn != nil {
				p.conn.Close()
			}
		}
	})
	c.wg.Wait()
}

func (c *Client) tunnelMTU() int64 {
	if c.mtu != 0 {
		return c.mtu - PktMin
	}
	return 0
}

// TunnelMTU is the largest IP packet the tunnel carries (0 until known).
func (c *Client) TunnelMTU() int64 { c.mu.Lock(); defer c.mu.Unlock(); return c.tunnelMTU() }

// Ready reports whether a path is running with a known MTU.
func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rate > 0 && c.tunnelMTU() > 0
}

// Inbox delivers decrypted IP packets from the server.
func (c *Client) Inbox() <-chan []byte { return c.inbox }

// PathStats is one path's public statistics.
type PathStats struct {
	Slot, Status, Pref                                   int
	Local, Reason, Role                                  string
	Enabled, Demoted, Bad                                bool
	MTU                                                  int64
	RTTMS, JitterMS                                      float64
	TxBytes, RxBytes, TxPackets, RxPackets, DataTx, Loss int64
}

// Stats is the python stats() document.
type Stats struct {
	Ready     bool
	TunnelMTU int64
	Errors    map[string]int
	Paths     []PathStats
}

func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Stats{Ready: c.rate > 0 && c.tunnelMTU() > 0, TunnelMTU: c.tunnelMTU(), Errors: map[string]int{}}
	for k, v := range c.errors {
		s.Errors[k] = v
	}
	for _, p := range c.paths {
		s.Paths = append(s.Paths, PathStats{Slot: p.slot, Local: p.localIP, Enabled: p.enabled, Reason: p.reason, Role: p.role, Status: p.status, MTU: p.mtuOK,
			RTTMS: float64(p.rtt.val) / 1000, JitterMS: float64(p.rtt.vr) / 1000, Pref: p.pref, Demoted: p.demoted, Bad: p.bad, TxBytes: p.tx.bytes, RxBytes: p.rx.bytes,
			TxPackets: p.tx.total, RxPackets: p.rx.total, DataTx: p.dataTx, Loss: p.tx.loss})
	}
	return s
}

// SetRoles applies link roles: primary and secondary aggregate, backup is hot
// standby, never is off.
func (c *Client) SetRoles(roles []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(roles) != len(c.paths) {
		return errors.New("one valid role per path is required")
	}
	for _, r := range roles {
		if _, ok := rolePref[r]; !ok && r != "never" {
			return errors.New("one valid role per path is required")
		}
	}
	for i, p := range c.paths {
		role := roles[i]
		if role == p.role {
			continue
		}
		p.role = role
		p.basePref = rolePrefOr(role, p.basePref)
		if role == "never" && p.enabled {
			p.enabled, p.reason = false, "role never"
		} else if role != "never" && !p.enabled && p.reason == "role never" {
			p.enabled, p.reason = p.hasSock, ""
		}
		p.pref = p.basePref
		if p.demoted {
			p.pref += Demotion
		}
	}
	return nil
}

// SetRates sets per-link speed limits in Mbit/s (0 = unlimited). Upload caps
// what we send; download is advertised so the server sends no faster.
func (c *Client) SetRates(up, down []float64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(up) != len(c.paths) || len(down) != len(c.paths) {
		return errors.New("one limit per path is required")
	}
	for i, p := range c.paths {
		if up[i] < 0 || down[i] < 0 {
			return errors.New("limits must not be negative")
		}
		if up[i] != 0 {
			p.txMaxRate = int64(up[i] * 125_000)
		} else {
			p.txMaxRate = c.rateBps
		}
		if down[i] != 0 {
			p.rxMaxRate = int64(down[i] * 125_000)
		} else {
			p.rxMaxRate = c.rateBps
		}
		if p.fixedRate == 0 {
			cur := p.tx.rate
			if cur == 0 {
				cur = p.txMaxRate
			}
			p.tx.rate = min(cur, p.txMaxRate)
		} else {
			p.tx.rate = p.txMaxRate
		}
	}
	return nil
}

// --- data plane ---------------------------------------------------------------

// Send encrypts and sends one IP packet. Normal traffic is striped by rate
// weight; urgent traffic uses the single best path (lowest predicted latency,
// not suspect). False if not ready or throttled.
func (c *Client) Send(packet []byte, urgent bool) bool {
	if len(packet) == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.send(packet, urgent)
}

func (c *Client) send(packet []byte, urgent bool) bool {
	if c.window < 1500 {
		c.errors["dropped_window"]++
		return false
	}
	if c.mtu != 0 && int64(len(packet))+PktMin > c.mtu {
		return false
	}
	now := c.clockNow()
	wire := c.kx.encrypt(now, packet)
	cursor := int64(binary.LittleEndian.Uint16(wire[len(wire)-2:]))
	var p *path
	if urgent {
		p = c.bestPath()
	} else {
		p = c.selectPath(cursor)
	}
	if p == nil {
		c.errors["no_path"]++
		return false
	}
	p.idle = now
	p.dataTx++
	c.sendPath(p, now, wire)
	return true
}

func predictedMS(p *path) float64 {
	if p.rtt.setup {
		return float64(p.rtt.val)/2000 + 2*float64(p.rtt.vr)/1000
	}
	return 1000.0
}

func (c *Client) bestPath() *path {
	var usable []*path
	for _, p := range c.paths {
		if p.enabled && p.status == Running {
			usable = append(usable, p)
		}
	}
	if len(usable) == 0 {
		return nil
	}
	suspect := func(p *path) bool { return p.bad || p.msg.sent >= 2 }
	sort.SliceStable(usable, func(i, j int) bool {
		a, b := usable[i], usable[j]
		if suspect(a) != suspect(b) {
			return !suspect(a)
		}
		return predictedMS(a) < predictedMS(b)
	})
	return usable[0]
}

func (c *Client) selectPath(cursor int64) *path {
	k := (cursor * c.rate) >> 16
	for _, p := range c.paths {
		if p.status != Running || !p.enabled {
			continue
		}
		if k < p.tx.rate {
			return p
		}
		k -= p.tx.rate
	}
	return nil
}

// --- control plane ------------------------------------------------------------

func (c *Client) sendMsg(p *path, now, sentTime, fwBytes, fwTotal, size int64) {
	size = min(max(size, PktMin+MsgSize), PktMax)
	var mtu int64
	if p.mtuProbe == 0 {
		mtu = p.mtuLast
	}
	m := Msg{SentTime: sentTime, PKey: c.kx.local, TxBytes: p.tx.bytes, TxTotal: p.tx.total, RxBytes: p.rx.bytes, RxTotal: p.rx.total, FwBytes: fwBytes, FwTotal: fwTotal,
		MaxRate: p.rxMaxRate, Beat: p.beat, MTU: mtu, Pref: byte(p.pref), Loss: byte(min(p.tx.loss, 255)), FixedRate: byte(p.fixedRate), LossLimit: byte(p.lossLimit), Addr: p.remote}
	plain := make([]byte, size-PktMin)
	copy(plain, m.Pack())
	c.sendPath(p, now, Seal(c.kx.private.enc, store(now|1, TimeSize), plain))
}

func (c *Client) recvMsg(p *path, now, headerTime, size int64, plain []byte) {
	m, err := UnpackMsg(plain)
	if err != nil {
		return
	}
	if m.SentTime == 0 {
		return // the server never initiates; only echoes of our probes are meaningful
	}
	p.rtt.update(tmask(now - m.SentTime))
	txBytes, txTotal := m.FwBytes, m.FwTotal
	rxBytes, rxTotal := m.RxBytes, m.RxTotal
	ms := &p.msg
	if m.SentTime > ms.txTime && txBytes > ms.txBytes && headerTime > ms.rxTime && rxBytes > ms.rxBytes {
		if ms.set && p.status > Probing {
			c.updateRL(p, tmask(m.SentTime-ms.txTime), txBytes-ms.txBytes, txTotal-ms.txTotal, tmask(headerTime-ms.rxTime), rxBytes-ms.rxBytes, rxTotal-ms.rxTotal)
		}
		ms.txTime, ms.rxTime, ms.txBytes, ms.rxBytes = m.SentTime, headerTime, txBytes, rxBytes
		ms.txTotal, ms.rxTotal, ms.set = txTotal, rxTotal, true
	}
	p.rx.loss = int64(m.Loss)
	ms.sent = 0
	p.updateMTU(size)
	if p.mtuLast != 0 && p.mtuLast == m.MTU {
		p.mtuOK = p.mtuLast
	}
	if !bytesEqual(m.PKey, c.kx.remote) {
		if !c.kx.derive(m.PKey) {
			c.errors["keyx"]++
			return
		}
	} else {
		c.kx.useNext = true // the peer has echoed our key: switch to the session keys
	}
	c.sendMsg(p, now, headerTime, m.TxBytes, m.TxTotal, size)
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

func (c *Client) updateRL(p *path, txDt, txBytes, txPkt, rxDt, rxBytes, rxPkt int64) {
	ms := &p.msg
	if rxDt != 0 && rxDt > txDt+(txDt>>3) {
		if p.fixedRate == 0 {
			p.tx.rate = (7 * rxBytes * OneSec) / (8 * rxDt)
		}
	} else {
		txAcc, rxAcc := ms.txAcc+txPkt, ms.rxAcc+rxPkt
		if txAcc > 1000 {
			if txAcc >= rxAcc {
				p.tx.loss = (txAcc - rxAcc) * 255 / txAcc
			}
			ms.txAcc, ms.rxAcc = txAcc-(txAcc>>4), rxAcc-(rxAcc>>4)
		} else {
			ms.txAcc, ms.rxAcc = txAcc, rxAcc
		}
		if p.fixedRate == 0 {
			p.tx.rate += p.tx.rate / 10
		}
	}
	p.tx.rate = min(p.tx.rate, p.txMaxRate)
}

// onPacket handles one datagram received on path p from address.
func (c *Client) onPacket(p *path, from netip.AddrPort, packet []byte) {
	if !p.enabled || len(packet) <= PktMin || from != p.remote {
		return
	}
	now := c.clockNow()
	headerTime := load(packet[:TimeSize])
	if tmask(now-headerTime) > TimeTol && tmask(headerTime-now) > TimeTol {
		c.errors["clocksync"]++
		return
	}
	isMsg := headerTime&1 != 0
	var plain []byte
	if isMsg {
		plain = Unseal(c.kx.private.dec, packet)
	} else {
		plain = c.kx.decrypt(packet)
	}
	if plain == nil || (isMsg && len(plain) < MsgSize) {
		c.errors["decrypt"]++
		return
	}
	if isMsg {
		c.recvMsg(p, now, headerTime, int64(len(packet)), plain)
	} else {
		p.idle = now
		if len(plain) >= 20 && (plain[0]>>4 == 4 || plain[0]>>4 == 6) {
			select {
			case c.inbox <- plain:
			default:
				c.errors["malformed"]++
			}
		} else {
			c.errors["malformed"]++
		}
	}
	p.rx.total++
	p.rx.time = now
	p.rx.bytes += int64(len(packet))
	c.lastRecv = now
}

// --- periodic work (mud_update) -----------------------------------------------

func (c *Client) pathUpdate(p *path) bool {
	if p.msg.sent >= MsgSentMax {
		if p.mtuProbe != 0 {
			p.updateMTU(0)
			p.msg.sent = 0
		} else {
			p.msg.sent = MsgSentMax
			p.status = Degraded
			return false
		}
	}
	if p.mtuOK == 0 {
		p.status = Probing
		return false
	}
	if p.tx.loss > p.lossLimit || p.rx.loss > p.lossLimit {
		p.status = Lossy
		return false
	}
	if p.pref > c.pref {
		p.status = Ready
	} else if p.status != Running {
		p.status, p.idle = Running, c.clockNow()
	}
	return true
}

func (c *Client) pathTrack(p *path, now int64) int64 {
	timeout := p.beat
	switch p.status {
	case Running:
		if tmask(now-p.idle) >= OneSec {
			timeout = Keepalive
		}
	case Ready:
		// Beyond the original: keep a hot standby (or a demoted path) measured
		// and alive with a cheap probe.
		timeout = max(p.beat, 250*OneMsec)
	case Degraded, Lossy, Probing:
	default:
		return now
	}
	if p.msg.time == 0 || tmask(now-p.msg.time) >= timeout {
		p.msg.sent++
		p.msg.time = now
		c.sendMsg(p, now, 0, 0, 0, p.mtuProbe)
		now = c.clockNow()
	}
	return now
}

func (c *Client) assess(nowS float64) {
	if nowS-c.lastAssess < 0.05 {
		return
	}
	elapsed := 0.05
	if c.lastAssess != 0 {
		elapsed = nowS - c.lastAssess
	}
	c.lastAssess = nowS
	for _, p := range c.paths {
		if !p.enabled {
			p.bad = false
			continue
		}
		rtt, jitter := float64(p.rtt.val)/1000, float64(p.rtt.vr)/1000
		known := p.rtt.setup && p.mtuOK != 0
		if known {
			if !p.baseRTTSet {
				p.baseRTT, p.baseRTTSet = rtt, true
			} else {
				p.baseRTT = math.Min(rtt, p.baseRTT+0.5*elapsed) // relearns over time
			}
		}
		base := p.baseRTT
		if !p.baseRTTSet || base == 0 {
			base = rtt
		}
		spike := known && rtt > 2*base+20
		var reasons []string
		if p.msg.sent >= 2 {
			reasons = append(reasons, "missed")
		}
		if spike {
			reasons = append(reasons, "latency")
		}
		if known && jitter > c.jitterMS {
			reasons = append(reasons, "jitter")
		}
		if p.tx.loss > 5 {
			reasons = append(reasons, "loss")
		}
		p.bad, p.reason = len(reasons) > 0, strings.Join(reasons, ",")
		if p.bad {
			if p.badSince == 0 {
				p.badSince = nowS
			}
			p.goodSince = 0
		} else {
			if p.goodSince == 0 {
				p.goodSince = nowS
			}
			p.badSince = 0
		}
	}
	for _, p := range c.paths {
		if !p.enabled {
			continue
		}
		otherGood := false
		for _, o := range c.paths {
			if o != p && o.enabled && !o.bad && o.mtuOK != 0 {
				otherGood = true
			}
		}
		switch {
		case !p.demoted && p.bad && otherGood && nowS-p.badSince >= c.demoteAfter:
			p.demoted, p.pref = true, p.basePref+Demotion
			c.errors["demotions"]++
		case p.demoted && !p.bad && nowS-p.goodSince >= c.recoverySec:
			p.demoted, p.pref = false, p.basePref
		case p.demoted && p.bad && !otherGood:
			p.demoted, p.pref = false, p.basePref // nothing better to prefer: do not strand the traffic
		}
	}
}

func (c *Client) update() {
	c.assess(c.mono())
	now := c.clockNow()
	c.kx.rotateIfDue(now, KxTimeout)
	pref, nextPref, rate, mtu := 255, 255, int64(0), int64(0)
	var active []*path
	for _, p := range c.paths {
		if p.enabled {
			active = append(active, p)
		} else {
			p.status = Probing
		}
	}
	for _, p := range active {
		if c.pathUpdate(p) {
			if nextPref > p.pref && p.pref > c.pref {
				nextPref = p.pref
			}
			pref = min(pref, p.pref)
			if p.status == Running {
				rate += p.tx.rate
			}
		}
		if p.mtuOK != 0 && (mtu == 0 || mtu > p.mtuOK) {
			mtu = p.mtuOK
		}
		now = c.pathTrack(p, now)
	}
	if rate != 0 {
		c.pref = pref
	} else {
		c.pref = nextPref
		for _, p := range active {
			if c.pathUpdate(p) && p.status == Running {
				rate += p.tx.rate
			}
		}
	}
	c.rate, c.mtu = rate, mtu
	elapsed := tmask(now - c.windowTime)
	if elapsed > OneMsec {
		c.window += c.rate * elapsed / OneSec
		c.windowTime = now
	}
	c.window = min(c.window, c.rate*100*OneMsec/OneSec)
}

// Rebind describes a slot that could not be bound by UpdatePaths.
type Rebind struct {
	Slot  int
	Error string
}

// UpdatePaths follows adapter changes: only slots whose address, interface or
// availability changed are rebound (new socket, fresh path state); usage
// counters carry over. The slot count must stay the same. indices and
// available may be nil.
func (c *Client) UpdatePaths(localIPs []string, indices []int, available []bool) ([]Rebind, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.stop:
		return nil, errors.New("client is closed")
	default:
	}
	if len(localIPs) != len(c.paths) {
		return nil, errors.New("path slots must remain stable")
	}
	if (indices != nil && len(indices) != len(c.paths)) || (available != nil && len(available) != len(c.paths)) {
		return nil, errors.New("interface_indices and available must have one entry per path")
	}
	var errs []Rebind
	for slot, ip := range localIPs {
		old := c.paths[slot]
		index := 0
		if indices != nil {
			index = indices[slot]
		}
		up := available == nil || available[slot]
		wanted := up && old.role != "never" && ip != "" && ip != "0.0.0.0"
		if ip == old.localIP && index == old.index && wanted == old.enabled {
			continue
		}
		if old.conn != nil {
			old.conn.Close() // its reader exits on the closed socket
		}
		pref := -1
		if old.basePref != rolePrefOr(old.role, -1) {
			pref = old.basePref // a custom preference survives
		}
		fresh := c.newPath(slot, ip, index, up, old.role, pref)
		fresh.tx.total, fresh.tx.bytes = old.tx.total, old.tx.bytes
		fresh.rx.total, fresh.rx.bytes = old.rx.total, old.rx.bytes
		if wanted && !fresh.enabled {
			errs = append(errs, Rebind{Slot: slot, Error: fresh.reason})
		}
		c.paths[slot] = fresh
		if c.started && fresh.conn != nil {
			c.wg.Add(1)
			go c.reader(fresh)
		}
	}
	c.errors["rebinds"]++
	return errs, nil
}
