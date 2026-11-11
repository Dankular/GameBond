// Package client is the Go client run loop: one pinned UDP socket per uplink,
// the GB03 client Receiver and Sender, a bounded transmit queue, and a single
// goroutine that owns all protocol state. Callers feed packets in with Send and
// get delivered packets from the Deliver callback.
package client

import (
	"context"
	"errors"
	"fmt"
	"gamebond.local/nativeedge/hrclock"
	"net"
	"net/netip"
	"sync"
	"time"

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/carrier"
	"gamebond.local/nativeedge/uplink"
)

// spinWindow is how close to the next paced release the loop stops sleeping.
const spinWindow = time.Millisecond

type Config struct {
	Key, Session []byte
	Server       netip.AddrPort
	Uplinks      []uplink.Spec
	// Available parks initially offline slots; nil means all are available.
	Available []bool
	// Policies has one entry per uplink; nil means no LINK_POLICY is sent.
	Policies []bond.PathPolicy
	MTU      int  // 0 means 1400
	Discover bool // per-path MTU discovery
	Failover bool // suspect-path tracking and replay
	FlowPinning bool // pin bulk flows to one path with fast reroute
	CoDel       bool // per-flow CoDel with ECN marking on the bulk queue
	// InitialMbps and MaxMbps seed the per-uplink congestion budget.
	InitialMbps, MaxMbps float64
	QueuePackets         int // 0 means 40000
	QueueBytes           int // 0 means 64 MiB
	// Deliver receives each payload the server sends, in reordered sequence; it runs on a dedicated delivery
	// goroutine, so it may block briefly but must not be shared with the loop.
	Deliver func(payload []byte)
	// Outer, when set, wraps every usable uplink in a carrier.Socket: after
	// FallbackAfter seconds without authenticated UDP the path moves to a
	// stream carrier and tries UDP again every RecoveryInterval.
	Outer *carrier.Settings
	// QoS enables adaptive duplication of tagged traffic (nil: off, as a
	// client built without adaptive_qos settings).
	QoS *bond.QoSSettings
	// LossTracking sends replicated packets as DATA_COPY (config loss_tracking).
	LossTracking bool
	// DelayControl cuts a path's bulk rate when a standing queue builds (config delay_control).
	DelayControl bool
}

type inbound struct {
	local    int
	frame    []byte
	endpoint netip.AddrPort
	rx       *carrier.Received // set when the datagram came through a carrier socket
}

type Client struct {
	cfg      Config
	recv     *bond.Receiver
	sender   *bond.Sender
	queue    *bond.TransmitQueue
	qos      *bond.AdaptiveQoS
	conns    []*net.UDPConn
	socks    []*carrier.Socket // nil entry: plain UDP
	lastRec  []time.Time
	loop     LoopStats
	incoming chan inbound
	submit   chan bond.QueuedPacket
	policies chan []bond.PathPolicy
	hints    chan pathHintMsg
	once     sync.Once
	mu       sync.Mutex
	snapshot Snapshot
	specs    []uplink.Spec
	avail    []bool
	rebind   chan rebindRequest
	runCtx   context.Context
	done     chan struct{}
	rebinds  uint64
}

// Snapshot is a copy of the loop's counters, safe to read from any goroutine.
// LoopStats counts slow work inside the client loop (milliseconds).
type LoopStats struct {
	Iterations, BusyOver5, BusyOver20      uint64
	BusyMaxMS                              float64
	Delivered, DeliverOver2, DeliverOver10 uint64
	DeliverDropped                         uint64 // delivery queue full: the consumer (netstack pipe) fell behind
	DeliverMaxMS                           float64
}

type Snapshot struct {
	Ready    int
	Uplinks  int
	Receiver bond.ReceiverStats
	Sender   bond.SenderStats
	Reorder  bond.ReorderStats
	// Loop times how long the single protocol loop is busy per wakeup and how
	// long handing a packet to the device takes; anything slow here delays every packet.
	Loop     LoopStats
	Queue    bond.TransmitQueueStats
	Paths    []bond.PathSnapshot
	Rejected uint64
	// Rebinds counts uplinks rebound by UpdateUplinks (Python path_rebinds).
	Rebinds uint64
	// Carrier has one entry per uplink; Mode is empty for a plain UDP uplink.
	Carrier []carrier.Stats
	// QoS is AdaptiveQoS.Stats; nil when adaptive QoS is not configured.
	QoS map[string]any
}

var ErrConfig = errors.New("client: invalid configuration")

// New opens the uplink sockets and builds the protocol state. Nothing is sent
// until Run.
func New(cfg Config) (*Client, error) {
	if len(cfg.Uplinks) == 0 || len(cfg.Uplinks) > 8 || !cfg.Server.IsValid() || cfg.Deliver == nil {
		return nil, ErrConfig
	}
	if cfg.Policies != nil && len(cfg.Policies) != len(cfg.Uplinks) {
		return nil, fmt.Errorf("%w: %d policies for %d uplinks", ErrConfig, len(cfg.Policies), len(cfg.Uplinks))
	}
	if cfg.Available != nil && len(cfg.Available) != len(cfg.Uplinks) {
		return nil, ErrConfig
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	if cfg.QueuePackets == 0 {
		cfg.QueuePackets = 40000
	}
	if cfg.QueueBytes == 0 {
		cfg.QueueBytes = 64 << 20
	}
	if cfg.InitialMbps == 0 {
		cfg.InitialMbps = 10
	}
	if cfg.MaxMbps == 0 {
		cfg.MaxMbps = 100
	}
	codec, err := bond.NewCodec(cfg.Key, cfg.Session, "client")
	if err != nil {
		return nil, err
	}
	r, err := bond.NewReceiver(codec, cfg.MTU)
	if err != nil {
		return nil, err
	}
	if err = r.SetPathMTUDiscovery(cfg.Discover); err != nil {
		return nil, err
	}
	s, err := bond.NewSender(r, cfg.InitialMbps, cfg.MaxMbps)
	if err != nil {
		return nil, err
	}
	s.EnableFailover(cfg.Failover)
	s.SetFlowPinning(cfg.FlowPinning)
	s.EnableLossTracking(cfg.LossTracking)
	s.EnableDelayControl(cfg.DelayControl)
	q, err := bond.NewTransmitQueue(s, cfg.QueuePackets, cfg.QueueBytes)
	if err == nil {
		q.EnableCoDel(cfg.CoDel)
	}
	if err != nil {
		return nil, err
	}
	var qos *bond.AdaptiveQoS
	if cfg.QoS != nil {
		if qos, err = bond.NewAdaptiveQoS(*cfg.QoS); err != nil {
			return nil, err
		}
		q.SetQoS(qos)
	}
	c := &Client{qos: qos, cfg: cfg, recv: r, sender: s, queue: q, incoming: make(chan inbound, 1024), submit: make(chan bond.QueuedPacket, 4096), policies: make(chan []bond.PathPolicy, 4), hints: make(chan pathHintMsg, 16), rebind: make(chan rebindRequest), done: make(chan struct{}), specs: append([]uplink.Spec(nil), cfg.Uplinks...)}
	now := hrclock.Now()
	for i, spec := range cfg.Uplinks {
		live := cfg.Available == nil || cfg.Available[i]
		spec.DontFragment = cfg.Discover
		if !live {
			spec = uplink.Spec{Addr: netip.MustParseAddr("127.0.0.1")}
		}
		conn, err := uplink.Open(spec)
		if err != nil {
			c.closeConns()
			return nil, fmt.Errorf("uplink %d: %w", i, err)
		}
		c.conns = append(c.conns, conn)
		var sock *carrier.Socket
		if live && cfg.Outer != nil && spec.Addr.IsValid() && !spec.Addr.IsUnspecified() {
			sock, err = carrier.NewSocket(conn, net.UDPAddrFromAddrPort(cfg.Server), cfg.Key, cfg.Session, *cfg.Outer, uplink.Control(spec))
			if err != nil {
				c.closeConns()
				return nil, fmt.Errorf("uplink %d carrier: %w", i, err)
			}
		}
		c.socks = append(c.socks, sock)
		c.avail = append(c.avail, live)
		c.lastRec = append(c.lastRec, time.Time{})
		if err = r.AddClientPath(i, cfg.Server, now); err != nil {
			c.closeConns()
			return nil, err
		}
		if !live {
			if err = r.RebindClientPath(i, now, true); err != nil {
				c.closeConns()
				return nil, err
			}
		}
	}
	if cfg.Policies != nil {
		if err = r.SetClientLinkPolicies(cfg.Policies, now); err != nil {
			c.closeConns()
			return nil, err
		}
	}
	return c, nil
}

func (c *Client) closeConns() {
	for _, s := range c.socks {
		if s != nil {
			s.Close()
		}
	}
	for _, conn := range c.conns {
		conn.Close()
	}
}

// Send queues a payload for the server. It never blocks: false means the
// submission buffer is full and the packet was dropped.
func (c *Client) Send(payload []byte, flow string, ttl time.Duration) bool {
	return c.Submit(bond.QueuedPacket{Payload: payload, Flow: flow, Expires: hrclock.Now().Add(ttl)})
}

// Submit queues a fully described packet (priority, replication, tag, expiry).
func (c *Client) Submit(p bond.QueuedPacket) bool {
	p.Payload = append([]byte(nil), p.Payload...)
	select {
	case c.submit <- p:
		return true
	default:
		c.mu.Lock()
		c.snapshot.Rejected++
		c.mu.Unlock()
		return false
	}
}

func (c *Client) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshot
}

func (c *Client) write(d bond.Datagram) error {
	if d.Local < 0 || d.Local >= len(c.conns) {
		return fmt.Errorf("client: datagram for unknown uplink %d", d.Local)
	}
	if s := c.socks[d.Local]; s != nil {
		var err error
		if d.DirectUDP {
			err = s.SendUDPProbe(d.Frame)
		} else {
			err = s.Send(d.Frame)
		}
		if errors.Is(err, carrier.ErrWouldBlock) {
			return nil // reconnecting or queue full: dropped and counted by the carrier
		}
		return err
	}
	_, err := c.conns[d.Local].WriteToUDPAddrPort(d.Frame, d.Endpoint)
	return err
}

// Run drives the protocol until ctx ends, then closes the sockets.
func (c *Client) Run(ctx context.Context) error {
	defer c.closeConns()
	c.runCtx = ctx
	defer close(c.done)
	for i := range c.conns {
		c.startReader(ctx, i, c.conns[i], c.socks[i])
	}
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	closed := make(chan time.Time) // always ready: used to poll instead of sleeping
	close(closed)
	nextBulk := hrclock.Now()
	lastSnap := time.Time{}
	// Delivery runs on its own goroutine: handing a packet to the application
	// side can block (a full pipe to the netstack), and the loop must keep
	// reading the uplinks, pacing and answering feedback meanwhile. One
	// consumer keeps the reordered sequence intact.
	deliverQ := make(chan []byte, 4096)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-deliverQ:
				t0 := hrclock.Now()
				c.cfg.Deliver(p)
				ms := float64(hrclock.Now().Sub(t0)) / float64(time.Millisecond)
				c.mu.Lock()
				l := &c.loop
				l.Delivered++
				if ms > l.DeliverMaxMS {
					l.DeliverMaxMS = ms
				}
				if ms > 2 {
					l.DeliverOver2++
				}
				if ms > 10 {
					l.DeliverOver10++
				}
				c.mu.Unlock()
			}
		}
	}()
	handle := func(res bond.ReceiveResult, now time.Time) {
		c.sender.Controls(res, now, c.write)
		for _, p := range res.Deliver {
			select {
			case deliverQ <- p:
			default:
				c.mu.Lock()
				c.loop.DeliverDropped++
				c.mu.Unlock()
			}
		}
	}
	for {
		// A paced backlog whose next release is under a millisecond away is
		// waited for by polling: sleeping on a timer would overshoot by the OS
		// timer granularity and cap throughput at the pacer's burst per wakeup.
		spin := c.queue.Stats().QueuedPackets > 0 && nextBulk.Sub(hrclock.Now()) < spinWindow
		var idle <-chan time.Time = tick.C
		if spin {
			idle = closed
		}
		select {
		case <-ctx.Done():
			return nil
		case d := <-c.incoming:
			res, err := c.recv.ReceiveVia(d.local, d.frame, d.endpoint, hrclock.Now(), d.rx == nil || d.rx.Transport == "udp")
			if err != nil {
				return err
			}
			if d.rx != nil {
				if res.Authenticated {
					c.socks[d.local].NoteAuthenticated(*d.rx)
				}
				if res.ReturnToUDP {
					c.socks[d.local].ReturnToUDP()
				}
			}
			handle(res, hrclock.Now())
		case p := <-c.submit:
			// Urgent traffic never waits for the bulk pacing timer: nextBulk is
			// a bulk wakeup, up to 5 ms ahead after every pump.
			if c.queue.Enqueue(p) && (p.Priority || p.Replicate || bond.IsTCPControl(p.Payload)) {
				nextBulk = hrclock.Now()
			}
		case policies := <-c.policies:
			if err := c.recv.SetClientLinkPolicies(policies, hrclock.Now()); err != nil {
				return err
			}
		case req := <-c.rebind:
			req.reply <- c.doRebind(req)
		case <-idle:
		}
		now := hrclock.Now()
		busyFrom := now
		if err := c.carrierTick(now); err != nil {
			return err
		}
		res, err := c.recv.Tick(now)
		if err != nil {
			return err
		}
		handle(res, now)
		if err = c.sender.Maintenance(now, c.write); err != nil {
			return err
		}
		if c.queue.Stats().QueuedPackets > 0 && !now.Before(nextBulk) {
			if nextBulk, err = c.queue.Pump(now, c.write); err != nil {
				return err
			}
		}
		{
			l := &c.loop
			l.Iterations++
			if ms := float64(hrclock.Now().Sub(busyFrom)) / float64(time.Millisecond); ms > 5 {
				l.BusyOver5++
				if ms > 20 {
					l.BusyOver20++
				}
				if ms > l.BusyMaxMS {
					l.BusyMaxMS = ms
				}
			}
		}
		if now.Sub(lastSnap) >= 100*time.Millisecond {
			lastSnap = now
			c.mu.Lock()
			c.snapshot.Ready, c.snapshot.Uplinks = c.recv.ReadyPaths(now), len(c.conns)
			c.snapshot.Receiver, c.snapshot.Sender = c.recv.Stats(), c.sender.Stats()
			c.snapshot.Reorder = c.recv.ReorderStats()
			c.snapshot.Loop = c.loop
			c.snapshot.Queue, c.snapshot.Paths = c.queue.Stats(), c.sender.Paths(now)
			if c.qos != nil {
				c.snapshot.QoS = c.qos.Stats(now)
			}
			if c.cfg.Outer != nil {
				c.snapshot.Carrier = make([]carrier.Stats, len(c.socks))
				for i, s := range c.socks {
					if s != nil {
						c.snapshot.Carrier[i] = s.Stats()
					}
				}
			}
			c.mu.Unlock()
		}
	}
}

// carrierTick asks each carrier socket to consider falling back and, while one
// is on a stream, probes UDP with a recovery HELLO every RecoveryInterval.
func (c *Client) carrierTick(now time.Time) error {
	if c.cfg.Outer == nil {
		return nil
	}
	interval := time.Duration(c.cfg.Outer.RecoveryInterval * float64(time.Second))
	for i, s := range c.socks {
		if s == nil {
			continue
		}
		s.Tick(now)
		if now.Sub(c.lastRec[i]) < interval || s.Stats().Mode == "udp" {
			continue
		}
		c.lastRec[i] = now
		d, err := c.recv.StartRecovery(i, now)
		if err != nil {
			continue // path not configured or no entropy: try again next interval
		}
		_ = c.write(d) // a failed probe is simply retried next interval
	}
	return nil
}

// SetPolicies installs a new per-uplink policy set (one entry per uplink, by
// index). The server must acknowledge it before an uplink carries payload
// again, exactly as at start-up.
func (c *Client) SetPolicies(policies []bond.PathPolicy) error {
	if len(policies) != len(c.conns) {
		return ErrConfig
	}
	select {
	case c.policies <- append([]bond.PathPolicy(nil), policies...):
		return nil
	default:
		return errors.New("client: policy update queue full")
	}
}

type pathHintMsg struct {
	uplink   int
	degraded bool
	ttl      time.Duration
	reason   string
}

// SetPathHint tells the sender an uplink is degraded (or recovered) according
// to an outside signal, for example the Starlink dish's own statistics. Bulk
// avoids a hinted uplink while another works and adaptive redundancy turns on;
// the hint expires after ttl so a silent monitor cannot pin it forever.
func (c *Client) SetPathHint(uplink int, degraded bool, ttl time.Duration, reason string) {
	select {
	case c.hints <- pathHintMsg{uplink, degraded, ttl, reason}:
	default:
	}
}

// startReader forwards what one uplink receives into the loop. It ends when
// its socket is closed (including when the slot is rebound).
func (c *Client) startReader(ctx context.Context, i int, conn *net.UDPConn, sock *carrier.Socket) {
	if sock != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case r, ok := <-sock.Recv():
					if !ok {
						return
					}
					select {
					case c.incoming <- inbound{i, r.Packet, c.cfg.Server, &r}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
		return
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			select {
			case c.incoming <- inbound{i, append([]byte(nil), buf[:n]...), from, nil}:
			case <-ctx.Done():
				return
			}
		}
	}()
}

// RebindError reports an uplink that could not be bound by UpdateUplinks.
type RebindError struct {
	Slot  int
	Error string
}

type rebindRequest struct {
	specs []uplink.Spec
	avail []bool
	reply chan rebindResult
}

type rebindResult struct {
	errs []RebindError
	err  error
}

// ErrNotRunning is returned by UpdateUplinks when Run is not active.
var ErrNotRunning = errors.New("client: not running")

// UpdateUplinks follows adapter changes (update_client_paths): only uplinks
// whose spec or availability changed get a new socket and a restarted path;
// the peer session and the other uplinks keep running. An unavailable or
// unbindable uplink is parked on a loopback socket, so it never handshakes,
// and a bind failure is reported per slot. available may be nil (all up).
// The slot count must not change.
func (c *Client) UpdateUplinks(specs []uplink.Spec, available []bool) ([]RebindError, error) {
	if len(specs) != len(c.specs) || (available != nil && len(available) != len(specs)) {
		return nil, fmt.Errorf("%w: client path slots must remain stable", ErrConfig)
	}
	if available == nil {
		available = make([]bool, len(specs))
		for i := range available {
			available[i] = true
		}
	}
	req := rebindRequest{append([]uplink.Spec(nil), specs...), append([]bool(nil), available...), make(chan rebindResult, 1)}
	select {
	case c.rebind <- req:
	case <-c.done:
		return nil, ErrNotRunning
	case <-time.After(5 * time.Second):
		return nil, ErrNotRunning
	}
	r := <-req.reply
	return r.errs, r.err
}

// doRebind runs on the loop goroutine, which owns the socket slices.
func (c *Client) doRebind(req rebindRequest) rebindResult {
	var res rebindResult
	now := hrclock.Now()
	for i, spec := range req.specs {
		if spec == c.specs[i] && req.avail[i] == c.avail[i] {
			continue
		}
		live := req.avail[i]
		var conn *net.UDPConn
		var sock *carrier.Socket
		if live {
			var err error
			dfSpec := spec
			dfSpec.DontFragment = c.cfg.Discover
			if conn, err = uplink.Open(dfSpec); err != nil {
				res.errs = append(res.errs, RebindError{i, err.Error()})
				live = false
			} else if c.cfg.Outer != nil && spec.Addr.IsValid() && !spec.Addr.IsUnspecified() {
				if sock, err = carrier.NewSocket(conn, net.UDPAddrFromAddrPort(c.cfg.Server), c.cfg.Key, c.cfg.Session, *c.cfg.Outer, uplink.Control(spec)); err != nil {
					conn.Close()
					res.errs = append(res.errs, RebindError{i, err.Error()})
					live = false
				}
			}
		}
		if !live {
			var err error
			if conn, err = uplink.Open(uplink.Spec{Addr: netip.MustParseAddr("127.0.0.1")}); err != nil {
				res.err = err
				return res
			}
			sock = nil
		}
		oldConn, oldSock := c.conns[i], c.socks[i]
		c.conns[i], c.socks[i], c.specs[i], c.avail[i] = conn, sock, spec, live
		c.lastRec[i] = time.Time{}
		if err := c.recv.RebindClientPath(i, now, !live); err != nil {
			res.err = err
			return res
		}
		if oldSock != nil {
			oldSock.Close()
		}
		oldConn.Close()
		c.startReader(c.runCtx, i, conn, sock)
		c.mu.Lock()
		c.rebinds++
		c.snapshot.Rebinds = c.rebinds
		c.mu.Unlock()
	}
	return res
}

// DFEnforced reports, per uplink, whether don't-fragment is set (Python's
// mtu.df_enforced). False for an unavailable uplink or when discovery is off.
func (c *Client) DFEnforced() []bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]bool, len(c.conns))
	for i, conn := range c.conns {
		out[i] = conn != nil && c.cfg.Discover && uplink.DFEnforced(conn)
	}
	return out
}
