package client

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Core/buildinfo"
)

// Exit-server failover.
//
// The first server in the configuration is the primary exit and the others are standbys. The active
// server is judged by one thing: authenticated frames arriving from it. BFD and supervision frames
// flow every few tens of milliseconds even when idle, so silence means the server, or the way to it,
// is gone.
//
// Silence alone does not move the client, because a local outage (both links down for a few seconds)
// looks identical and a switch resets every bonded TCP stream, which would turn a survivable gap into a
// dropped connection. Instead the client sends real handshakes to the standbys while the active server
// is silent and only moves to one that answers. If no standby answers, the problem is on this side
// and nothing is switched. A standby is promoted with the handshake it just completed, so no traffic
// waits for a second one.
//
// While the active server is healthy the standbys are still probed now and then, so a standby that
// has stopped working is reported before it is needed.

const (
	defaultFailoverAfter = 2 * time.Second
	minFailoverAfter     = 500 * time.Millisecond
)

// Probe timing; variables so tests can shorten them.
var (
	probeEvery   = 30 * time.Second
	probeFirst   = 5 * time.Second
	probeTimeout = 3 * time.Second
)

// ExitServer is one configured exit as the status document reports it.
type ExitServer struct {
	Addr   netip.AddrPort
	Active bool
	// State is "active", "reachable" (a probe handshake completed), "unreachable" (a probe got no
	// answer) or "unknown" (not probed yet).
	State string
	// HandshakeMS is how long the last successful probe handshake took.
	HandshakeMS float64
	// CheckedAt is when the last probe finished; zero if it never ran.
	CheckedAt time.Time
	// Failures counts the times this server was dropped as the active exit.
	Failures uint64
	// WireTX and WireRX are the bytes this exit has carried since the client started, headers
	// included. A standby carries nothing but its probes, which are not counted.
	WireTX, WireRX uint64
}

// ExitStatus describes the exit servers and the failovers so far.
type ExitStatus struct {
	Active  netip.AddrPort
	Primary netip.AddrPort
	Servers []ExitServer
	// Switches counts failovers; LastSwitch and LastReason describe the latest.
	Switches   uint64
	LastSwitch time.Time
	LastReason string
	// SilentMS is how long the active server has been silent right now.
	SilentMS float64
	// Probing is true while the client is looking for a standby because the active exit is silent.
	Probing bool
}

type exitInfo struct {
	state       string
	handshakeMS float64
	checked     time.Time
	failures    uint64
}

type candidate struct {
	addr    netip.AddrPort
	st      *stack
	ready   bool
	readyAt time.Time
}

// standby is a set of throwaway client receivers, one per standby server, handshaking over the live
// plain-UDP uplinks while the real session carries on.
type standby struct {
	started  time.Time
	failover bool // the active server is silent: a ready candidate is promoted
	cands    []*candidate
}

// failoverState is touched only by the loop goroutine, except servers/active which are guarded by mu.
type failoverState struct {
	servers     []netip.AddrPort // [0] is the primary
	active      int
	after       time.Duration
	lastAuth    time.Time
	activeSince time.Time
	nextProbe   time.Time
	standby     *standby
	info        map[netip.AddrPort]*exitInfo
	switches    uint64
	lastSwitch  time.Time
	lastReason  string
	silent      time.Duration
	// traffic accumulates the wire bytes each exit has carried; lastTX/lastRX are the active
	// stack's path totals at the previous sample (a new stack after a switch starts from zero).
	traffic        map[netip.AddrPort]*[2]uint64
	lastTX, lastRX uint64
}

// serverAddr is the active server; the carrier readers call it from their own goroutines.
func (c *Client) serverAddr() netip.AddrPort { return *c.serverPtr.Load() }

func (c *Client) setServer(a netip.AddrPort) { c.serverPtr.Store(&a) }


func (c *Client) initFailover(now time.Time) {
	f := &c.fo
	f.servers = append([]netip.AddrPort{c.cfg.Server}, c.cfg.Backups...)
	f.after = c.cfg.FailoverAfter
	if f.after == 0 {
		f.after = defaultFailoverAfter
	}
	f.after = max(f.after, minFailoverAfter)
	f.lastAuth, f.activeSince = now, now
	f.nextProbe = now.Add(probeFirst)
	f.info = map[netip.AddrPort]*exitInfo{}
	for _, s := range f.servers {
		f.info[s] = &exitInfo{state: "unknown"}
	}
	c.setServer(c.cfg.Server)
}

// stack is one complete protocol state: receiver, sender, transmit queue and adaptive QoS. The
// sender must exist before the receiver accepts a path, so the three are always built together.
type stack struct {
	recv   *bond.Receiver
	sender *bond.Sender
	queue  *bond.TransmitQueue
	qos    *bond.AdaptiveQoS
}

// buildStack builds a client stack aimed at server over the current uplinks. With plainOnly it
// leaves out uplinks that run through a carrier socket: a standby probe cannot use those.
func (c *Client) buildStack(server netip.AddrPort, now time.Time, plainOnly bool) (*stack, error) {
	cfg := c.cfg
	codec, err := bond.NewCodec(cfg.Key, cfg.Session, "client")
	if err != nil {
		return nil, err
	}
	r, err := bond.NewReceiver(codec, cfg.MTU)
	if err != nil {
		return nil, err
	}
	r.SetVersion(buildinfo.Commit)
	if err = r.SetPathMTUDiscovery(cfg.Discover); err != nil {
		return nil, err
	}
	s, err := bond.NewSender(r, cfg.InitialMbps, cfg.MaxMbps)
	if err != nil {
		return nil, err
	}
	s.EnableFailover(cfg.Failover)
	s.SetFlowPinning(cfg.FlowPinning)
	s.SetStripeAbove(cfg.StripeAbove)
	s.SetParityRows(cfg.ParityRowsMin, cfg.ParityRowsMax)
	s.EnableLossTracking(cfg.LossTracking)
	s.EnableDelayControl(cfg.DelayControl)
	q, err := bond.NewTransmitQueue(s, cfg.QueuePackets, cfg.QueueBytes)
	if err != nil {
		return nil, err
	}
	q.EnableCoDel(cfg.CoDel)
	var qos *bond.AdaptiveQoS
	if cfg.QoS != nil {
		if qos, err = bond.NewAdaptiveQoS(*cfg.QoS); err != nil {
			return nil, err
		}
		q.SetQoS(qos)
	}
	for i := range c.conns {
		if plainOnly && c.socks[i] != nil {
			continue
		}
		if err = r.AddClientPath(i, server, now); err != nil {
			return nil, err
		}
		if !c.avail[i] {
			if err = r.RebindClientPath(i, now, true); err != nil {
				return nil, err
			}
		}
	}
	if cfg.Policies != nil && !plainOnly {
		if err = r.SetClientLinkPolicies(cfg.Policies, now); err != nil {
			return nil, err
		}
	}
	return &stack{r, s, q, qos}, nil
}

// adopt makes st the live protocol state.
func (c *Client) adopt(st *stack) {
	c.mu.Lock()
	c.recv, c.sender, c.queue, c.qos = st.recv, st.sender, st.queue, st.qos
	c.mu.Unlock()
}

// receiver is the live receiver for goroutines other than the loop.
func (c *Client) receiver() *bond.Receiver {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recv
}

// failoverTick runs once per loop pass.
func (c *Client) failoverTick(now time.Time) error {
	f := &c.fo
	if len(f.servers) < 2 {
		return nil
	}
	anyLive := false
	for i := range c.conns {
		if c.avail[i] && c.socks[i] == nil {
			anyLive = true
		}
	}
	if !anyLive {
		// No adapter is up: the silence is ours, not the server's.
		f.lastAuth = now
	}
	f.silent = now.Sub(f.lastAuth)
	failover := f.silent >= f.after
	st := f.standby
	switch {
	case st != nil && st.failover && !failover:
		f.standby = nil // the active server answered again
	case st != nil && !st.failover && failover:
		f.standby = nil // start over as a failover search
	case st == nil && failover && anyLive:
		f.standby = nil
		if err := c.startStandby(now, true); err != nil {
			return err
		}
	case st == nil && !failover && anyLive && !now.Before(f.nextProbe):
		f.nextProbe = now.Add(probeEvery)
		if err := c.startStandby(now, false); err != nil {
			return err
		}
	}
	if f.standby != nil {
		return c.standbyTick(now)
	}
	return nil
}

func (c *Client) startStandby(now time.Time, failover bool) error {
	f := &c.fo
	st := &standby{started: now, failover: failover}
	for i, s := range f.servers {
		if i == f.active {
			continue
		}
		bs, err := c.buildStack(s, now, true)
		if err != nil {
			return err
		}
		st.cands = append(st.cands, &candidate{addr: s, st: bs})
	}
	f.standby = st
	return nil
}

// standbyInbound feeds a datagram from a standby server to its probe receiver. It reports whether
// the datagram belonged to one.
func (c *Client) standbyInbound(d inbound, now time.Time) bool {
	st := c.fo.standby
	if st == nil || d.rx != nil {
		return false
	}
	for _, cand := range st.cands {
		if cand.addr != d.endpoint {
			continue
		}
		res, err := cand.st.recv.ReceiveVia(d.local, d.frame, d.endpoint, now, true)
		if err == nil {
			for _, o := range res.Send {
				c.writeStandby(o)
			}
		}
		return true
	}
	return false
}

func (c *Client) writeStandby(d bond.Datagram) {
	if d.Local < 0 || d.Local >= len(c.conns) || c.socks[d.Local] != nil {
		return
	}
	_, _ = c.conns[d.Local].WriteToUDPAddrPort(d.Frame, d.Endpoint)
}

func (c *Client) standbyTick(now time.Time) error {
	f := &c.fo
	st := f.standby
	for _, cand := range st.cands {
		res, err := cand.st.recv.Tick(now)
		if err != nil {
			continue
		}
		for _, o := range res.Send {
			c.writeStandby(o)
		}
		if !cand.ready && cand.st.recv.ReadyPaths(now) > 0 {
			cand.ready, cand.readyAt = true, now
		}
	}
	if st.failover {
		for _, cand := range st.cands {
			if cand.ready {
				return c.promote(cand, now)
			}
		}
		return nil
	}
	// A health probe: finished when every candidate answered or the time is up.
	done := now.Sub(st.started) >= probeTimeout
	all := true
	for _, cand := range st.cands {
		all = all && cand.ready
	}
	if !done && !all {
		return nil
	}
	for _, cand := range st.cands {
		info := f.info[cand.addr]
		info.checked = now
		if cand.ready {
			info.state, info.handshakeMS = "reachable", float64(cand.readyAt.Sub(st.started))/float64(time.Millisecond)
		} else {
			info.state = "unreachable"
		}
	}
	f.standby = nil
	return nil
}

// promote makes a standby that has just completed its handshake the active exit.
func (c *Client) promote(cand *candidate, now time.Time) error {
	f := &c.fo
	from := f.servers[f.active]
	silent := f.silent
	reason := fmt.Sprintf("no reply from %s for %d ms; %s answered", from.Addr(), silent.Milliseconds(), cand.addr.Addr())
	old := c.receiver()
	old.NoteComponent("exit-node", false, reason)
	dir := c.outageDirNow()
	if dir != "" {
		old.CloseOutageLog()
	}
	c.adopt(cand.st)
	if dir != "" {
		_ = cand.st.recv.OpenOutageLog(dir)
	}
	cand.st.recv.NoteComponent("exit-node", true, "now using "+cand.addr.String())
	idx := 0
	for i, s := range f.servers {
		if s == cand.addr {
			idx = i
		}
	}
	f.info[from].failures++
	f.info[from].state = "unreachable"
	f.info[from].checked = now
	f.active = idx
	f.lastTX, f.lastRX = 0, 0
	f.lastAuth, f.activeSince = now, now
	f.standby = nil
	f.switches++
	f.lastSwitch, f.lastReason = time.Now(), reason
	f.nextProbe = now.Add(probeEvery)
	c.setServer(cand.addr)
	if c.cfg.OnSwitch != nil {
		c.cfg.OnSwitch(from, cand.addr, reason)
	}
	return nil
}

// exitStatus is read by the snapshot code on the loop goroutine.
func (c *Client) exitStatus() ExitStatus {
	f := &c.fo
	var tx, rx uint64
	for _, p := range c.snapshot.Paths {
		tx, rx = tx+p.WireTX, rx+p.WireRX
	}
	if f.traffic == nil {
		f.traffic = map[netip.AddrPort]*[2]uint64{}
	}
	acc := f.traffic[f.servers[f.active]]
	if acc == nil {
		acc = &[2]uint64{}
		f.traffic[f.servers[f.active]] = acc
	}
	if tx >= f.lastTX {
		acc[0] += tx - f.lastTX
	} else {
		acc[0] += tx
	}
	if rx >= f.lastRX {
		acc[1] += rx - f.lastRX
	} else {
		acc[1] += rx
	}
	f.lastTX, f.lastRX = tx, rx
	st := ExitStatus{Active: f.servers[f.active], Primary: f.servers[0], Switches: f.switches, LastSwitch: f.lastSwitch,
		LastReason: f.lastReason, SilentMS: float64(f.silent) / float64(time.Millisecond), Probing: f.standby != nil && f.standby.failover}
	for i, s := range f.servers {
		info := f.info[s]
		e := ExitServer{Addr: s, Active: i == f.active, State: info.state, HandshakeMS: info.handshakeMS, CheckedAt: info.checked, Failures: info.failures}
		if e.Active {
			e.State = "active"
		}
		if a := f.traffic[s]; a != nil {
			e.WireTX, e.WireRX = a[0], a[1]
		}
		st.Servers = append(st.Servers, e)
	}
	return st
}


func (c *Client) outageDirNow() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.outageDir
}
