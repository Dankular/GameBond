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
// dropped connection. The evidence that the problem is the active server and not this side is a
// standby that is answering at the same moment.
//
// Each standby is therefore kept warm: a real client receiver handshaken with it over the live
// plain-UDP uplinks, exchanging its own keepalives, ready to take over without another handshake.
// Two thresholds decide when to move:
//
//   - fast: the active server has been silent for a few multiples of the longest gap between its frames
//     seen lately (floor minFastAfter), and a standby has been heard within aliveWithin. The active
//     server and the standby share this PC's links, so a standby that is audible while the active
//     server is not points at the server.
//   - slow: the active server has been silent for FailoverAfter and a standby is ready, although not
//     heard in the last instant. Used when the standby evidence is stale.
//
// If no standby is ready, nothing is switched however long the silence lasts. A standby that has
// stopped working is reported while the active server is still healthy, before it is needed.

const (
	defaultFailoverAfter = time.Second
	minFailoverAfter     = 500 * time.Millisecond
	// minFastAfter is the lowest silence that can trigger the fast path.
	minFastAfter = 300 * time.Millisecond
	// aliveWithin is how recently a standby must have sent an authenticated frame to count as audible.
	aliveWithin = 300 * time.Millisecond
	// fastFactor scales the longest recent gap between active-server frames into the fast threshold.
	fastFactor = 4
	// gapSeconds is how many one-second maxima of that gap are kept; fastSamples is how many must exist
	// before the fast threshold is trusted.
	gapSeconds  = 30
	fastSamples = 3
)

// Probe timing; variables so tests can shorten them. probeFirst delays building the warm standbys at
// start, probeTimeout is how long a first handshake may take before the standby is called unreachable,
// and probeEvery is how long an unanswered standby waits before it is rebuilt from scratch.
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
	addr     netip.AddrPort
	st       *stack
	ready    bool
	readyAt  time.Time
	started  time.Time // when this candidate's handshake began (reset when it is rebuilt)
	lastAuth time.Time // the last authenticated frame from it
}

// standby is the warm set: one client receiver per standby server, kept handshaken over the live
// plain-UDP uplinks while the real session carries on.
type standby struct {
	cands []*candidate
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
	// fast is the adaptive silence threshold (see the package comment); it equals after until enough
	// seconds of frames have been seen. gaps holds the longest inter-frame gap of each recent second.
	fast      time.Duration
	gapPrev   time.Time
	gapSec    time.Time
	gapMax    time.Duration
	gaps      [gapSeconds]time.Duration
	gapCount  int
	searching bool
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
	f.fast = f.after
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

// noteAuth records an authenticated frame from the active server and keeps the adaptive threshold.
func (c *Client) noteAuth(now time.Time) {
	f := &c.fo
	if !f.gapPrev.IsZero() {
		if g := now.Sub(f.gapPrev); g > f.gapMax && g < f.after {
			f.gapMax = g // a longer silence is an outage, not the line's own rhythm
		}
	}
	f.gapPrev, f.lastAuth = now, now
	if f.gapSec.IsZero() {
		f.gapSec = now
	}
	if now.Sub(f.gapSec) >= time.Second {
		f.gaps[f.gapCount%gapSeconds] = f.gapMax
		f.gapCount++
		f.gapSec, f.gapMax = now, 0
		f.fast = f.adaptive()
	}
}

// adaptive is fastFactor times the second-largest of the recent one-second maxima (so one stray stall
// does not dominate), within [minFastAfter, after].
func (f *failoverState) adaptive() time.Duration {
	n := min(f.gapCount, gapSeconds)
	if n < fastSamples {
		return f.after
	}
	var top1, top2 time.Duration
	for _, g := range f.gaps[:n] {
		switch {
		case g > top1:
			top1, top2 = g, top1
		case g > top2:
			top2 = g
		}
	}
	return min(max(fastFactor*top2, minFastAfter), f.after)
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
		f.lastAuth, f.gapPrev = now, time.Time{}
	}
	f.silent = now.Sub(f.lastAuth)
	f.searching = anyLive && f.silent >= f.fast
	suspect := f.silent >= max(f.fast/3, 100*time.Millisecond)
	if f.standby == nil && anyLive && (!now.Before(f.nextProbe) || suspect) {
		if err := c.startStandby(now); err != nil {
			return err
		}
	}
	if f.standby == nil {
		return nil
	}
	c.standbyTick(now)
	if !anyLive {
		return nil
	}
	var slow, fast *candidate
	for _, cand := range f.standby.cands {
		if !cand.ready {
			continue
		}
		if slow == nil {
			slow = cand
		}
		if fast == nil && now.Sub(cand.lastAuth) <= aliveWithin {
			fast = cand
		}
	}
	switch {
	case fast != nil && f.silent >= f.fast:
		return c.promote(fast, now)
	case slow != nil && f.silent >= f.after:
		return c.promote(slow, now)
	}
	return nil
}

func (c *Client) startStandby(now time.Time) error {
	f := &c.fo
	st := &standby{}
	for i, s := range f.servers {
		if i == f.active {
			continue
		}
		cand, err := c.newCandidate(s, now)
		if err != nil {
			return err
		}
		st.cands = append(st.cands, cand)
	}
	f.standby = st
	return nil
}

func (c *Client) newCandidate(addr netip.AddrPort, now time.Time) (*candidate, error) {
	bs, err := c.buildStack(addr, now, true)
	if err != nil {
		return nil, err
	}
	return &candidate{addr: addr, st: bs, started: now}, nil
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
			if res.Authenticated {
				cand.lastAuth = now
			}
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

// standbyTick keeps the warm candidates handshaking and their reported state current.
func (c *Client) standbyTick(now time.Time) {
	f := &c.fo
	for _, cand := range f.standby.cands {
		res, err := cand.st.recv.Tick(now)
		if err == nil {
			for _, o := range res.Send {
				c.writeStandby(o)
			}
		}
		info := f.info[cand.addr]
		ready := cand.st.recv.ReadyPaths(now) > 0
		switch {
		case ready && !cand.ready:
			cand.ready, cand.readyAt = true, now
			info.state, info.handshakeMS, info.checked = "reachable", float64(now.Sub(cand.started))/float64(time.Millisecond), now
		case !ready && cand.ready:
			cand.ready = false
			info.state, info.checked = "unreachable", now
		case !ready && info.state == "unknown" && now.Sub(cand.started) >= probeTimeout:
			info.state, info.checked = "unreachable", now
		}
		if !cand.ready && now.Sub(cand.started) >= probeEvery {
			// Never answered, or lost: start a fresh handshake rather than wait on an old one.
			if nc, err := c.newCandidate(cand.addr, now); err == nil {
				*cand = *nc
			}
		}
	}
}

// promote makes a warm standby the active exit.
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
	f.gapPrev, f.gapMax = time.Time{}, 0
	f.switches++
	f.lastSwitch, f.lastReason = time.Now(), reason
	// The promoted stack is no longer a standby; the old exit takes its place in the warm set so it is
	// noticed the moment it answers again.
	cands := make([]*candidate, 0, len(f.standby.cands))
	for _, x := range f.standby.cands {
		if x != cand {
			cands = append(cands, x)
		}
	}
	if nc, err := c.newCandidate(from, now); err == nil {
		cands = append(cands, nc)
	}
	f.standby.cands = cands
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
		LastReason: f.lastReason, SilentMS: float64(f.silent) / float64(time.Millisecond), Probing: f.searching}
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
