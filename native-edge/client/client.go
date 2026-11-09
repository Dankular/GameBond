// Package client is the Go client run loop: one pinned UDP socket per uplink,
// the GB03 client Receiver and Sender, a bounded transmit queue, and a single
// goroutine that owns all protocol state. Callers feed packets in with Send and
// get delivered packets from the Deliver callback.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/uplink"
)

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
}

type inbound struct {
	local    int
	frame    []byte
	endpoint netip.AddrPort
}

type Client struct {
	cfg      Config
	recv     *bond.Receiver
	sender   *bond.Sender
	queue    *bond.TransmitQueue
	conns    []*net.UDPConn
	incoming chan inbound
	submit   chan bond.QueuedPacket
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
	c := &Client{cfg: cfg, recv: r, sender: s, queue: q, incoming: make(chan inbound, 1024), submit: make(chan bond.QueuedPacket, 4096)}
	now := time.Now()
	for i, spec := range cfg.Uplinks {
		conn, err := uplink.Open(spec)
		if err != nil {
			c.closeConns()
			return nil, fmt.Errorf("uplink %d: %w", i, err)
		}
		c.conns = append(c.conns, conn)
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
	for _, conn := range c.conns {
		conn.Close()
	}
}

// Send queues a payload for the server. It never blocks: false means the
// submission buffer is full and the packet was dropped.
func (c *Client) Send(payload []byte, flow string, ttl time.Duration) bool {
	select {
	case c.submit <- bond.QueuedPacket{Payload: append([]byte(nil), payload...), Flow: flow, Expires: time.Now().Add(ttl)}:
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
	_, err := c.conns[d.Local].WriteToUDPAddrPort(d.Frame, d.Endpoint)
	return err
}

// Run drives the protocol until ctx ends, then closes the sockets.
func (c *Client) Run(ctx context.Context) error {
	defer c.closeConns()
	for i := range c.conns {
		go func(i int) {
			buf := make([]byte, 65536)
			for {
				n, from, err := c.conns[i].ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				select {
				case c.incoming <- inbound{i, append([]byte(nil), buf[:n]...), from}:
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	nextBulk := time.Now()
	lastSnap := time.Time{}
	handle := func(res bond.ReceiveResult, now time.Time) {
		c.sender.Controls(res, now, c.write)
		for _, p := range res.Deliver {
			c.cfg.Deliver(p)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case d := <-c.incoming:
			res, err := c.recv.ReceiveOn(d.local, d.frame, d.endpoint, time.Now())
			if err != nil {
				return err
			}
			handle(res, time.Now())
		case p := <-c.submit:
			c.queue.Enqueue(p)
		case <-tick.C:
		}
		now := time.Now()
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
			c.mu.Unlock()
		}
	}
}
