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
	// Policies has one entry per uplink; nil means no LINK_POLICY is sent.
	Policies []bond.PathPolicy
	MTU      int  // 0 means 1400
	Discover bool // per-path MTU discovery
	Failover bool // suspect-path tracking and replay
	// InitialMbps and MaxMbps seed the per-uplink congestion budget.
	InitialMbps, MaxMbps float64
	QueuePackets         int // 0 means 40000
	QueueBytes           int // 0 means 64 MiB
	// Deliver receives each payload the server sends; it runs on the loop
	// goroutine and must not block.
	Deliver func(payload []byte)
	// Outer, when set, wraps every usable uplink in a carrier.Socket: after
	// FallbackAfter seconds without authenticated UDP the path moves to a
	// stream carrier and tries UDP again every RecoveryInterval.
	Outer *carrier.Settings
	// QoS enables adaptive duplication of tagged traffic (nil: off, as a
	// client built without adaptive_qos settings).
	QoS *bond.QoSSettings
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
	incoming chan inbound
	submit   chan bond.QueuedPacket
	policies chan []bond.PathPolicy
	once     sync.Once
	mu       sync.Mutex
	snapshot Snapshot
}

// Snapshot is a copy of the loop's counters, safe to read from any goroutine.
type Snapshot struct {
	Ready    int
	Uplinks  int
	Receiver bond.ReceiverStats
	Sender   bond.SenderStats
	Queue    bond.TransmitQueueStats
	Paths    []bond.PathSnapshot
	Rejected uint64
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
	q, err := bond.NewTransmitQueue(s, cfg.QueuePackets, cfg.QueueBytes)
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
	c := &Client{qos: qos, cfg: cfg, recv: r, sender: s, queue: q, incoming: make(chan inbound, 1024), submit: make(chan bond.QueuedPacket, 4096), policies: make(chan []bond.PathPolicy, 4)}
	now := hrclock.Now()
	for i, spec := range cfg.Uplinks {
		conn, err := uplink.Open(spec)
		if err != nil {
			c.closeConns()
			return nil, fmt.Errorf("uplink %d: %w", i, err)
		}
		c.conns = append(c.conns, conn)
		var sock *carrier.Socket
		if cfg.Outer != nil && spec.Addr.IsValid() && !spec.Addr.IsUnspecified() {
			sock, err = carrier.NewSocket(conn, net.UDPAddrFromAddrPort(cfg.Server), cfg.Key, cfg.Session, *cfg.Outer, uplink.Control(spec))
			if err != nil {
				c.closeConns()
				return nil, fmt.Errorf("uplink %d carrier: %w", i, err)
			}
		}
		c.socks = append(c.socks, sock)
		c.lastRec = append(c.lastRec, time.Time{})
		if err = r.AddClientPath(i, cfg.Server, now); err != nil {
			c.closeConns()
			return nil, err
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
	for i := range c.conns {
		if c.socks[i] != nil {
			go func(i int) {
				for {
					select {
					case <-ctx.Done():
						return
					case r, ok := <-c.socks[i].Recv():
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
			}(i)
			continue
		}
		go func(i int) {
			buf := make([]byte, 65536)
			for {
				n, from, err := c.conns[i].ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				select {
				case c.incoming <- inbound{i, append([]byte(nil), buf[:n]...), from, nil}:
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	closed := make(chan time.Time) // always ready: used to poll instead of sleeping
	close(closed)
	nextBulk := hrclock.Now()
	lastSnap := time.Time{}
	handle := func(res bond.ReceiveResult, now time.Time) {
		c.sender.Controls(res, now, c.write)
		for _, p := range res.Deliver {
			c.cfg.Deliver(p)
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
			c.queue.Enqueue(p)
		case policies := <-c.policies:
			if err := c.recv.SetClientLinkPolicies(policies, hrclock.Now()); err != nil {
				return err
			}
		case <-idle:
		}
		now := hrclock.Now()
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
		if now.Sub(lastSnap) >= 100*time.Millisecond {
			lastSnap = now
			c.mu.Lock()
			c.snapshot.Ready, c.snapshot.Uplinks = c.recv.ReadyPaths(now), len(c.conns)
			c.snapshot.Receiver, c.snapshot.Sender = c.recv.Stats(), c.sender.Stats()
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
