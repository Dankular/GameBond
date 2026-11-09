package bond

import (
	"container/list"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"sort"
	"time"
)

type DatagramWriter func(Datagram) error
type sendFlow struct {
	key        string
	id, number uint64
	exhausted  bool
	last       time.Time
	lru        *list.Element
}
type SenderStats struct{ PayloadPackets, PayloadBytes, Copies, StripedPackets, PriorityCopies, TCPControlPackets, WireLimited, SocketErrors, RepairCopies, RepairRequests, MTUNoFit, FailoverSuspected, FailoverRecovered, FailoverReplayed, FailoverReplayDropped uint64 }

// Sender is the actor-owned transmit half. A caller retries a pending bulk
// packet at the returned time, servicing Receive/Tick/urgent queues meanwhile.
type Sender struct {
	r                 *Receiver
	flows             map[string]*sendFlow
	lru               list.List
	bulkClock         float64
	peer              [16]byte
	hasPeer           bool
	stats             SenderStats
	waitStart         time.Time
	waiters           []*Budget
	repairs           map[MissingPacket]*repairEntry
	repairOrder       list.List
	repairRequests    map[MissingPacket]*list.Element
	requestOrder      list.List
	asked             map[MissingPacket]*askedRepair
	askedOrder        list.List
	nextRepairRequest time.Time
	failover          bool
	lossTracking      bool
	replayQueue       []replayItem
}

func NewSender(r *Receiver, initial, maximum float64) (*Sender, error) {
	if r == nil || len(r.paths) != 0 {
		return nil, errors.New("configure native sender before accepting paths")
	}
	if _, err := NewBudget(initial, maximum); err != nil {
		return nil, err
	}
	r.initialRate = initial
	r.maxRate = maximum
	r.probeInterval = 250 * time.Millisecond
	return &Sender{r: r, flows: make(map[string]*sendFlow), repairs: make(map[MissingPacket]*repairEntry), repairRequests: make(map[MissingPacket]*list.Element), asked: make(map[MissingPacket]*askedRepair)}, nil
}

// EnableLossTracking makes replicated priority sends use DATA_COPY so the peer
// can score each path's copy (Python's loss_tracking option).
func (s *Sender) EnableLossTracking(on bool) { s.lossTracking = on }

func (s *Sender) Stats() SenderStats { return s.stats }
func (s *Sender) syncPeer() {
	if s.r.handshake.hasPeer && (!s.hasPeer || s.peer != s.r.handshake.peer) {
		clear(s.flows)
		s.lru.Init()
		s.bulkClock = 0
		s.peer = s.r.handshake.peer
		s.hasPeer = true
		s.waiters = nil
		s.waitStart = time.Time{}
		clear(s.repairs)
		s.repairOrder.Init()
		clear(s.repairRequests)
		s.requestOrder.Init()
		clear(s.asked)
		s.askedOrder.Init()
		s.nextRepairRequest = time.Time{}
		s.replayQueue = nil
	}
}
func (s *Sender) eligible(now time.Time, boost bool) []*receivePath {
	var all, primary, secondary, backup []*receivePath
	for _, p := range s.r.paths {
		if !p.ready || now.Sub(p.last) >= 3*time.Second {
			continue
		}
		if !s.r.policyEnabled {
			all = append(all, p)
			continue
		}
		if p.policy == nil || (s.r.role == "client" && !p.policyConfirmed) || p.policy.Blocked || p.policy.Role == Never {
			continue
		}
		switch p.policy.Role {
		case Primary:
			primary = append(primary, p)
		case Secondary:
			secondary = append(secondary, p)
		case Backup:
			backup = append(backup, p)
		}
	}
	if !s.r.policyEnabled {
		return all
	}
	if len(primary) > 0 {
		if boost {
			return append(primary, secondary...)
		}
		return primary
	}
	if len(secondary) > 0 {
		return secondary
	}
	return backup
}

// fitPaths keeps the paths whose discovered outbound MTU can carry a datagram of
// size bytes. When none fit it returns all of them: sending and risking loss
// beats silence, matching the Python fallback.
func (s *Sender) fitPaths(paths []*receivePath, size int) []*receivePath {
	if !s.r.mtuDiscovery {
		return paths
	}
	fit := make([]*receivePath, 0, len(paths))
	for _, p := range paths {
		if p.mtu == nil || p.mtu.PathMTU() >= size {
			fit = append(fit, p)
		} else {
			p.mtuSkips++
		}
	}
	if len(fit) == 0 {
		s.stats.MTUNoFit++
		return paths
	}
	return fit
}
func (s *Sender) written(d Datagram, p *receivePath, now time.Time, writer DatagramWriter) bool {
	timestamp := s.r.seconds(now)
	if p != nil && p.policy != nil && s.r.role == "client" && isPayloadKind(d.Frame) && (!p.policyConfirmed || p.policy.Blocked || p.policy.Role == Never) {
		return false
	}
	if p != nil && p.policy != nil && p.pacer.ReadyAt(len(d.Frame)+28, timestamp) > timestamp+.000001 {
		s.stats.WireLimited++
		s.cancelProbe(d)
		return false
	}
	err := writer(d)
	s.r.Sent(d, err)
	if err != nil {
		s.stats.SocketErrors++
		s.cancelProbe(d)
		return false
	}
	if p != nil {
		if p.policy != nil {
			p.pacer.Sent(len(d.Frame)+28, timestamp)
		}
		kind := d.Frame[36]
		if kind != Data && kind != Striped {
			p.budget.UnpacedSent(len(d.Frame), timestamp, true)
		}
		if kind == Probe {
			var token [24]byte
			packet, err := s.r.codec.tx.Open(nil, nonceFor(d.Frame), d.Frame[HeaderSize:], d.Frame[:HeaderSize])
			if err == nil {
				copy(token[:], packet)
				if pending, ok := s.r.probes[token]; ok {
					pending.at = now
					s.r.probes[token] = pending
					p.probeSent++
				}
			}
		}
	}
	return true
}
func nonceFor(frame []byte) []byte {
	nonce := make([]byte, 12)
	copy(nonce[4:], frame[37:45])
	return nonce
}
func (s *Sender) cancelProbe(d Datagram) {
	if len(d.Frame) < Overhead || d.Frame[36] != Probe {
		return
	}
	payload, err := s.r.codec.tx.Open(nil, nonceFor(d.Frame), d.Frame[HeaderSize:], d.Frame[:HeaderSize])
	if err == nil && len(payload) == 24 {
		var token [24]byte
		copy(token[:], payload)
		delete(s.r.probes, token)
	}
}

// Controls observes strict configured wire ceilings, including feedback/probes.
// A denied control write is retried by protocol timers, as in the Python Node.
func (s *Sender) Controls(result ReceiveResult, now time.Time, writer DatagramWriter) {
	s.syncPeer()
	for _, key := range result.Repairs {
		cached := s.repairs[key]
		if cached == nil || now.Sub(cached.at) >= time.Second || cached.attempts >= 2 {
			continue
		}
		if s.repairRequests[key] == nil {
			s.repairRequests[key] = s.requestOrder.PushBack(key)
		}
		if len(s.repairRequests) > 64 {
			oldest := s.requestOrder.Front()
			delete(s.repairRequests, oldest.Value.(MissingPacket))
			s.requestOrder.Remove(oldest)
		}
	}
	for _, key := range result.Unavailable {
		// The peer will never repair this packet: stop asking.
		if asked := s.asked[key]; asked != nil {
			asked.at, asked.attempts = now, 99
		}
	}
	for _, d := range result.Send {
		s.written(d, s.r.paths[PathKey{d.Local, d.Endpoint}], now, writer)
	}
}
func (s *Sender) Urgent(payload []byte, replicate bool, now time.Time, writer DatagramWriter) (int, error) {
	s.syncPeer()
	if len(payload)+Overhead > s.r.mtu {
		return 0, ErrFrame
	}
	paths := s.fitPaths(s.eligible(now, true), len(payload)+Overhead)
	sort.Slice(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		ca, cb := math.Inf(1), math.Inf(1)
		if a.hasRTT {
			ca = a.rtt/2 + 2*a.jitter
		}
		if b.hasRTT {
			cb = b.rtt/2 + 2*b.jitter
		}
		if ca == cb {
			return a.endpoint.Compare(b.endpoint) < 0
		}
		return ca < cb
	})
	kind := Data
	if replicate && s.lossTracking {
		kind = DataCopy
	}
	frame, err := s.r.codec.Encode(kind, payload)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, p := range paths {
		if s.written(Datagram{Endpoint: p.endpoint, Frame: frame, Local: p.local}, p, now, writer) {
			p.budget.UnpacedSent(len(frame), s.r.seconds(now), false)
			sent++
			s.stats.PriorityCopies++
			if !replicate {
				break
			}
		}
	}
	if sent > 0 {
		if IsTCPControl(payload) {
			s.stats.TCPControlPackets++
		}
		s.stats.PayloadPackets++
		s.stats.PayloadBytes += uint64(len(payload))
		s.stats.Copies += uint64(sent)
	}
	return sent, nil
}
func (s *Sender) flow(key string, now time.Time) (*sendFlow, error) {
	for s.lru.Len() > 0 {
		f := s.lru.Front().Value.(*sendFlow)
		if now.Sub(f.last) < 120*time.Second {
			break
		}
		delete(s.flows, f.key)
		s.lru.Remove(f.lru)
	}
	if f := s.flows[key]; f != nil && !f.exhausted {
		return f, nil
	}
	if f := s.flows[key]; f != nil {
		delete(s.flows, key)
		s.lru.Remove(f.lru)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return &sendFlow{key: key, id: binary.BigEndian.Uint64(id[:]), last: now}, nil
}

// ResumeBulk counts only real time spent with a bulk packet waiting. Call it
// after a timer/event wakeup while that packet remains queued, never for idle.
func (s *Sender) ResumeBulk(now time.Time) {
	if !s.waitStart.IsZero() {
		for _, b := range s.waiters {
			b.RecordWait(s.r.seconds(s.waitStart), s.r.seconds(now))
		}
	}
	s.waiters = nil
	s.waitStart = time.Time{}
}
func (s *Sender) Bulk(payload []byte, key string, now time.Time, writer DatagramWriter) (bool, time.Time, error) {
	s.syncPeer()
	if len(key) > 512 || len(payload)+Overhead+24 > s.r.mtu {
		return false, now, ErrFrame
	}
	if IsTCPControl(payload) {
		n, err := s.Urgent(payload, false, now, writer)
		return n > 0, now.Add(time.Millisecond), err
	}
	paths := s.eligible(now, true)
	if len(paths) == 0 {
		return false, now.Add(5 * time.Millisecond), nil
	}
	timestamp := s.r.seconds(now)
	size := len(payload) + Overhead + 24
	if s.failover {
		// A silent path is probably down: bulk avoids it while any other path is
		// alive; probes and gameplay copies still use it.
		var alive []*receivePath
		for _, p := range paths {
			if !s.pathSuspect(p, now) {
				alive = append(alive, p)
			}
		}
		if len(alive) > 0 {
			paths = alive
		}
	}
	paths = s.fitPaths(paths, size)
	ready := make(map[*receivePath]float64, len(paths))
	transit := make(map[*receivePath]float64, len(paths))
	primaryReady := false
	primaryDelayed := false
	for _, p := range paths {
		at, err := p.budget.ReadyAt(size, timestamp)
		if err != nil {
			return false, now, err
		}
		ready[p] = math.Max(at, p.pacer.ReadyAt(size+28, timestamp))
		if p.policy != nil && p.policy.Role == Primary {
			if ready[p] <= timestamp+.000001 {
				primaryReady = true
			}
			if p.budget.hasMin && p.budget.srtt-p.budget.minRTT > .025 {
				primaryDelayed = true
			}
		}
	}
	if s.r.policyEnabled && primaryReady && !primaryDelayed {
		selected := paths[:0]
		for _, p := range paths {
			if p.policy != nil && p.policy.Role == Primary {
				selected = append(selected, p)
			}
		}
		paths = selected
	}
	best := math.Inf(1)
	for _, p := range paths {
		probe := 0.
		if p.hasRTT {
			probe = p.rtt
		}
		transit[p] = p.budget.TransitSeconds(size, probe)
		best = math.Min(best, transit[p])
	}
	selected := paths[:0]
	margin := s.r.reorder.config.Timeout.Seconds()
	for _, p := range paths {
		threshold := margin
		if p.bulkFiltered {
			threshold *= .8
		}
		p.bulkFiltered = len(paths) > 1 && transit[p] > best+threshold
		if !p.bulkFiltered {
			selected = append(selected, p)
		}
	}
	paths = selected
	earliest := math.Inf(1)
	var available []*receivePath
	for _, p := range paths {
		earliest = math.Min(earliest, ready[p])
		if ready[p] <= timestamp+.000001 {
			available = append(available, p)
		}
	}
	if len(available) == 0 {
		s.waitStart = now
		s.waiters = nil
		for _, p := range paths {
			if p.budget.next > timestamp && ready[p] <= earliest+.000001 {
				s.waiters = append(s.waiters, p.budget)
			}
		}
		return false, now.Add(time.Duration(math.Max(0, earliest-timestamp) * float64(time.Second))), nil
	}
	minimum := math.Inf(1)
	for _, p := range available {
		minimum = math.Min(minimum, p.bulkFinish)
	}
	s.bulkClock = math.Max(s.bulkClock, minimum)
	sort.Slice(available, func(i, j int) bool {
		a, b := available[i], available[j]
		fa, fb := math.Max(a.bulkFinish, s.bulkClock), math.Max(b.bulkFinish, s.bulkClock)
		if fa != fb {
			return fa < fb
		}
		if ready[a]+transit[a] != ready[b]+transit[b] {
			return ready[a]+transit[a] < ready[b]+transit[b]
		}
		return a.endpoint.Compare(b.endpoint) < 0
	})
	f, err := s.flow(key, now)
	if err != nil {
		return false, now, err
	}
	for _, p := range available {
		body := make([]byte, 24+len(payload))
		binary.BigEndian.PutUint64(body, f.id)
		binary.BigEndian.PutUint64(body[8:], f.number)
		binary.BigEndian.PutUint64(body[16:], p.txEpoch)
		copy(body[24:], payload)
		frame, err := s.r.codec.Encode(Striped, body)
		if err != nil {
			return false, now, err
		}
		if s.written(Datagram{Endpoint: p.endpoint, Frame: frame, Local: p.local}, p, now, writer) {
			sequence := binary.BigEndian.Uint64(frame[37:])
			p.budget.Sent(sequence, len(frame), timestamp)
			p.bulkFinish = math.Max(p.bulkFinish, s.bulkClock) + float64(len(frame)+28)/p.budget.rate
			s.cacheRepair(MissingPacket{f.id, f.number}, payload, now, p)
			if f.number == math.MaxUint64 {
				f.exhausted = true
			} else {
				f.number++
			}
			f.last = now
			if f.lru == nil {
				f.lru = s.lru.PushBack(f)
				s.flows[key] = f
			} else {
				s.lru.MoveToBack(f.lru)
			}
			if len(s.flows) > 8192 {
				old := s.lru.Front().Value.(*sendFlow)
				delete(s.flows, old.key)
				s.lru.Remove(old.lru)
			}
			s.stats.PayloadPackets++
			s.stats.PayloadBytes += uint64(len(payload))
			s.stats.Copies++
			s.stats.StripedPackets++
			return true, now, nil
		}
	}
	return false, now.Add(time.Millisecond), nil
}

type PathSnapshot struct {
	Endpoint                                         netip.AddrPort
	Ready, Healthy                                   bool
	RTTMilliseconds, JitterMilliseconds              float64
	WireTX, WireRX, ProbeSent, ProbeAcked, ProbeLost uint64
	Policy                                           *PathPolicy
	Budget                                           map[string]any
	MTU                                              *MTUStats
	MTUAcks, MTUSkips                                uint64
	PolicyConfirmed                                  bool
	Suspect                                          bool
	Local                                            int // client uplink index (socket slot)
}

func (s *Sender) Paths(now time.Time) []PathSnapshot {
	var out []PathSnapshot
	for _, p := range s.r.paths {
		var policy *PathPolicy
		if p.policy != nil {
			copy := *p.policy
			policy = &copy
		}
		out = append(out, PathSnapshot{p.endpoint, p.ready, p.ready && now.Sub(p.last) < 3*time.Second, p.rtt * 1000, p.jitter * 1000, p.wireTX, p.wireRX, p.probeSent, p.probeAcked, p.probeLost, policy, p.budget.Stats(), mtuStats(p), p.mtuAcks, p.mtuSkips, p.policyConfirmed, p.suspect, p.local})
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Endpoint.Compare(out[j].Endpoint); c != 0 {
			return c < 0
		}
		return out[i].Local < out[j].Local
	})
	return out
}

func mtuStats(p *receivePath) *MTUStats {
	if p.mtu == nil {
		return nil
	}
	st := p.mtu.Stats()
	return &st
}

func isPayloadKind(frame []byte) bool {
	return len(frame) > 36 && (frame[36] == Data || frame[36] == DataCopy || frame[36] == Striped)
}
