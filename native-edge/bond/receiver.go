package bond

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"net/netip"
	"time"
)

// PathKey identifies a path by local socket index and remote endpoint. A server
// has a single bound socket (Local 0); a client binds one socket per uplink, so
// several paths share one remote endpoint and the index tells them apart.
type PathKey struct {
	Local  int
	Remote netip.AddrPort
}

type Datagram struct {
	Endpoint netip.AddrPort
	Frame    []byte
	// Local is the index of the socket to send from (0 for a server).
	Local int
}
type ReceiveResult struct {
	Send    []Datagram
	Deliver [][]byte
	Repairs []MissingPacket
}
type ReceiverStats struct {
	Authenticated, AuthenticationErrors, Malformed, Duplicates, FloorDrops, HandshakeRejected uint64
	PayloadPackets, PayloadBytes, WireRX, WireTX, SendErrors                                  uint64
	PeerRestarts, PathMigrations                                                              uint64
	FeedbackReceived, FeedbackRejected, FeedbackDuplicates                                    uint64
	PolicyDrops                                                                               uint64
}
type receivePath struct {
	hello                            ClientHandshake
	local                            int
	endpoint                         netip.AddrPort
	ready                            bool
	last                             time.Time
	lastSequence                     uint64
	txEpoch, rxEpoch                 uint64
	hasEpoch                         bool
	stripeBytes, stripeHighest       uint64
	stripeAt                         time.Time
	feedbackDue                      bool
	lastFeedback                     time.Time
	wireRX, wireTX                   uint64
	budget                           *Budget
	pacer                            WirePacer
	policy                           *PathPolicy
	policyRevision                   uint64
	bulkFinish                       float64
	bulkFiltered                     bool
	rtt, jitter                      float64
	hasRTT                           bool
	probeSent, probeAcked, probeLost uint64
	acceptedSequence, acceptedBytes  uint64
	hasFeedback                      bool
}
type pendingProbe struct {
	at   time.Time
	path *receivePath
}

// Receiver implements the GB03 server's authenticated receive half. It does not
// implement transmit congestion control, link quotas, or TUN routing; callers
// must not use it as a production edge server on its own.
type Receiver struct {
	role                 string
	codec                *Codec
	handshake            *ServerHandshake
	replay               ReplayWindow
	floor                uint64
	paths                map[PathKey]*receivePath
	reorder              *Reorder
	mtu                  int
	stats                ReceiverStats
	origin               time.Time
	initialRate, maxRate float64
	policyEnabled        bool
	probeInterval        time.Duration
	lastProbe            time.Time
	probes               map[[24]byte]pendingProbe
	reorderBase          time.Duration
}

func NewReceiver(codec *Codec, mtu int) (*Receiver, error) {
	if codec == nil || (codec.role != "server" && codec.role != "client") || mtu < Overhead+24 || mtu > 65507 {
		return nil, ErrFrame
	}
	r, _ := NewReorder(DefaultReorderConfig())
	return &Receiver{role: codec.role, codec: codec, handshake: NewServerHandshake(), paths: make(map[PathKey]*receivePath), reorder: r, mtu: mtu, initialRate: 1, maxRate: 100, probes: make(map[[24]byte]pendingProbe), reorderBase: 30 * time.Millisecond}, nil
}
func (r *Receiver) SetReorderTimeout(timeout time.Duration) error {
	if len(r.paths) > 0 || timeout < time.Millisecond || timeout > 200*time.Millisecond {
		return ErrFrame
	}
	r.reorderBase = timeout
	r.reorder.config.Timeout = timeout
	return nil
}
func (r *Receiver) seconds(now time.Time) float64 {
	if r.origin.IsZero() {
		r.origin = now
	}
	return math.Max(0, now.Sub(r.origin).Seconds())
}
func (r *Receiver) Stats() ReceiverStats       { return r.stats }
func (r *Receiver) ReorderStats() ReorderStats { return r.reorder.Stats() }
func (r *Receiver) ReadyPaths(now time.Time) int {
	n := 0
	for _, p := range r.paths {
		if p.ready && now.Sub(p.last) < 3*time.Second {
			n++
		}
	}
	return n
}
func (p *receivePath) key() PathKey { return PathKey{p.local, p.endpoint} }
func (r *Receiver) write(kind byte, payload []byte, local int, endpoint netip.AddrPort, out *ReceiveResult) error {
	frame, err := r.codec.Encode(kind, payload)
	if err != nil {
		return err
	}
	out.Send = append(out.Send, Datagram{Endpoint: endpoint, Frame: frame, Local: local})
	return nil
}

// Sent records only actual successful socket writes, including control and
// duplicate datagrams. Queuing a reply is not evidence it reached the socket.
func (r *Receiver) Sent(d Datagram, err error) {
	if err != nil {
		r.stats.SendErrors++
		return
	}
	n := uint64(len(d.Frame) + 28)
	r.stats.WireTX += n
	if p := r.paths[PathKey{d.Local, d.Endpoint}]; p != nil {
		p.wireTX += n
	}
}
func (r *Receiver) newPath(local int, endpoint netip.AddrPort, now time.Time) (*receivePath, error) {
	p, err := r.freshPath(local, endpoint, now)
	if err != nil {
		return nil, err
	}
	if len(r.paths) >= 8 {
		var oldest *receivePath
		for _, p := range r.paths {
			if oldest == nil || p.last.Before(oldest.last) {
				oldest = p
			}
		}
		delete(r.paths, oldest.key())
	}
	r.paths[p.key()] = p
	return p, nil
}

// Receive processes a datagram that arrived on the server's only socket.
func (r *Receiver) Receive(frame []byte, endpoint netip.AddrPort, now time.Time) (ReceiveResult, error) {
	return r.ReceiveOn(0, frame, endpoint, now)
}

// ReceiveOn processes a datagram that arrived on local socket index local.
func (r *Receiver) ReceiveOn(local int, frame []byte, endpoint netip.AddrPort, now time.Time) (ReceiveResult, error) {
	var out ReceiveResult
	key := PathKey{local, endpoint}
	timestamp := r.seconds(now)
	if len(frame) > r.mtu || !endpoint.IsValid() {
		r.stats.Malformed++
		return out, nil
	}
	packet, err := r.codec.Decode(frame)
	if err != nil {
		if err == ErrAuthentication {
			r.stats.AuthenticationErrors++
		} else {
			r.stats.Malformed++
		}
		return out, nil
	}
	h := packet.Header
	payload := packet.Payload
	if r.role == "client" && r.paths[key] == nil {
		r.stats.Malformed++ // configured peer only, as in the Python client
		return out, nil
	}
	r.stats.Authenticated++
	r.stats.WireRX += uint64(len(frame) + 28)
	p := r.paths[key]
	if p != nil {
		p.wireRX += uint64(len(frame) + 28)
	}
	if h.Kind >= Hello && h.Kind <= Ready {
		if r.role == "client" {
			return r.clientHandshake(p, packet, now)
		}
		if h.Kind == Reset && h.Sequence == math.MaxUint64 {
			r.stats.HandshakeRejected++
			return out, nil
		}
		reply, ok, err := r.handshake.Handle(packet, endpoint, now)
		if err != nil {
			return out, err
		}
		if !ok {
			r.stats.HandshakeRejected++
			return out, nil
		}
		if reply.AdoptPeer {
			if len(r.paths) > 0 {
				r.stats.PeerRestarts++
			}
			clear(r.paths)
			clear(r.probes)
			r.policyEnabled = false
			r.replay = ReplayWindow{}
			r.floor = h.Sequence + 1
			r.reorder, _ = NewReorder(DefaultReorderConfig())
			r.reorder.config.Timeout = r.reorderBase
			p = nil
		}
		if reply.Kind == Ready && reply.FreshProof {
			p = r.paths[key]
			if p == nil {
				p, err = r.newPath(local, endpoint, now)
				if err != nil {
					return out, err
				}
			}
			p.ready = true
			p.last = now
			if h.Sequence > p.lastSequence {
				p.lastSequence = h.Sequence
			}
		}
		err = r.write(reply.Kind, reply.Payload, local, endpoint, &out)
		return out, err
	}
	if !r.handshake.hasPeer || h.Prefix != r.handshake.peer {
		r.stats.HandshakeRejected++
		return out, nil
	}
	var epoch uint64
	hasEpoch := false
	if h.Kind == Probe && len(payload) == 24 {
		epoch = binary.BigEndian.Uint64(payload)
		hasEpoch = true
	}
	if h.Kind == Striped && len(payload) >= 24 {
		epoch = binary.BigEndian.Uint64(payload[16:])
		hasEpoch = true
	}
	var migrated *receivePath
	if hasEpoch && r.role == "server" {
		for _, candidate := range r.paths {
			if candidate.ready && candidate.hasEpoch && candidate.rxEpoch == epoch && candidate.key() != key {
				migrated = candidate
				break
			}
		}
	}
	if (p == nil && migrated == nil) || (p != nil && !p.ready) {
		r.stats.HandshakeRejected++
		return out, nil
	}
	if h.Sequence < r.floor {
		r.stats.FloorDrops++
		return out, nil
	}
	if !r.replay.Accept(h.Sequence) {
		r.stats.Duplicates++
		return out, nil
	}
	valid := true
	switch h.Kind {
	case Probe, Pong:
		valid = len(payload) == 24
	case Striped:
		valid = len(payload) >= 24
	case Feedback:
		valid = len(payload) == 28 && binary.BigEndian.Uint32(payload[24:]) <= 1000000
	case Repair:
		valid = len(payload) == 16
	case LinkPolicy:
		valid = len(payload) == 26
	case LinkPolicyAck:
		valid = false
	}
	if !valid {
		r.stats.Malformed++
		return out, nil
	}
	if migrated != nil {
		if h.Sequence <= migrated.lastSequence {
			r.stats.HandshakeRejected++
			return out, nil
		}
		delete(r.paths, migrated.key())
		migrated.local, migrated.endpoint = local, endpoint
		r.paths[key] = migrated
		p = migrated
		p.wireRX += uint64(len(frame) + 28)
		r.stats.PathMigrations++
	}
	if (h.Kind == Data || h.Kind == Striped) && p.policy != nil && (p.policy.Blocked || p.policy.Role == Never) {
		r.stats.PolicyDrops++
		return out, nil
	}
	p.last = now
	if h.Sequence > p.lastSequence {
		p.lastSequence = h.Sequence
	}
	if !p.hasEpoch && hasEpoch {
		p.rxEpoch = epoch
		p.hasEpoch = true
	}
	switch h.Kind {
	case Probe:
		err = r.write(Pong, payload, local, endpoint, &out)
	case Pong:
		var token [24]byte
		copy(token[:], payload)
		if probe, ok := r.probes[token]; ok && probe.path == p {
			delete(r.probes, token)
			p.probeAcked++
			sample := math.Max(.000001, now.Sub(probe.at).Seconds())
			if !p.hasRTT {
				p.rtt = sample
				p.jitter = sample / 2
				p.hasRTT = true
			} else {
				p.jitter = .75*p.jitter + .25*math.Abs(sample-p.rtt)
				p.rtt = .8*p.rtt + .2*sample
			}
			r.updateReorderBudget()
		}
	case Feedback:
		epoch, sequence, delivered := binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:]), binary.BigEndian.Uint64(payload[16:])
		if epoch == p.txEpoch && p.hasFeedback && sequence == p.acceptedSequence && delivered == p.acceptedBytes {
			r.stats.FeedbackDuplicates++
		} else if epoch == p.txEpoch && p.budget.Acknowledge(sequence, delivered, timestamp, binary.BigEndian.Uint32(payload[24:])) {
			p.hasFeedback = true
			p.acceptedSequence = sequence
			p.acceptedBytes = delivered
			r.stats.FeedbackReceived++
		} else {
			r.stats.FeedbackRejected++
		}
	case LinkPolicy:
		revision, policy, decodeErr := decodePolicy(payload)
		if decodeErr != nil || (revision == p.policyRevision && p.policy != nil && policy != *p.policy) {
			r.stats.Malformed++
			break
		}
		if p.policy == nil || revision >= p.policyRevision {
			p.policy = &policy
			p.policyRevision = revision
			r.policyEnabled = true
			p.pacer.SetRate(policy.DownloadMbps, timestamp)
		}
		ack := make([]byte, 32)
		binary.BigEndian.PutUint64(ack, p.policyRevision)
		binary.BigEndian.PutUint64(ack[8:], p.txEpoch)
		binary.BigEndian.PutUint64(ack[16:], p.wireTX+Overhead+32+28)
		binary.BigEndian.PutUint64(ack[24:], p.wireRX)
		err = r.write(LinkPolicyAck, ack, local, endpoint, &out)
	case Repair:
		out.Repairs = append(out.Repairs, MissingPacket{binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:])})
	case Striped:
		if !p.hasEpoch || (p.rxEpoch != epoch && h.Sequence > p.stripeHighest) {
			p.rxEpoch = epoch
			p.hasEpoch = true
			p.stripeBytes = 0
			p.stripeAt = time.Time{}
		}
		if p.rxEpoch == epoch {
			p.stripeBytes += uint64(len(frame))
			if p.stripeAt.IsZero() || h.Sequence > p.stripeHighest {
				p.stripeHighest = h.Sequence
				p.stripeAt = now
			}
			p.feedbackDue = true
		}
		r.stats.PayloadPackets++
		r.stats.PayloadBytes += uint64(len(payload) - 24)
		out.Deliver = r.reorder.Push(binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:]), payload[24:], now)
	case Data:
		r.stats.PayloadPackets++
		r.stats.PayloadBytes += uint64(len(payload))
		out.Deliver = append(out.Deliver, payload)
	}
	return out, err
}
func (r *Receiver) Tick(now time.Time) (ReceiveResult, error) {
	out := ReceiveResult{Deliver: r.reorder.Poll(now)}
	for _, p := range r.paths {
		if p.policy != nil && (p.policy.Blocked || p.policy.Role == Never) {
			continue
		}
		if !p.ready || p.stripeAt.IsZero() || now.Sub(p.last) >= 3*time.Second {
			continue
		}
		interval := 100 * time.Millisecond
		if p.feedbackDue {
			interval = 20 * time.Millisecond
		}
		if !p.lastFeedback.IsZero() && now.Sub(p.lastFeedback) < interval {
			continue
		}
		payload := make([]byte, 28)
		binary.BigEndian.PutUint64(payload, p.rxEpoch)
		binary.BigEndian.PutUint64(payload[8:], p.stripeHighest)
		binary.BigEndian.PutUint64(payload[16:], p.stripeBytes)
		hold := now.Sub(p.stripeAt) / time.Microsecond
		if hold < 0 {
			hold = 0
		}
		if hold > 1000000 {
			hold = 1000000
		}
		binary.BigEndian.PutUint32(payload[24:], uint32(hold))
		if err := r.write(Feedback, payload, p.local, p.endpoint, &out); err != nil {
			return out, err
		}
		p.feedbackDue = false
		p.lastFeedback = now
	}
	if r.probeInterval > 0 && (r.lastProbe.IsZero() || now.Sub(r.lastProbe) >= r.probeInterval) {
		r.lastProbe = now
		for token, probe := range r.probes {
			if now.Sub(probe.at) >= 3*time.Second {
				probe.path.probeLost++
				delete(r.probes, token)
			}
		}
		for _, p := range r.paths {
			if r.role == "client" && (!p.ready || now.Sub(p.last) >= 3*time.Second) {
				if err := r.clientPoll(p, now, &out); err != nil {
					return out, err
				}
				continue
			}
			if !p.ready || now.Sub(p.last) >= 3*time.Second || (p.policy != nil && (p.policy.Blocked || p.policy.Role == Never)) {
				continue
			}
			var token [24]byte
			binary.BigEndian.PutUint64(token[:], p.txEpoch)
			if _, err := rand.Read(token[8:]); err != nil {
				return out, err
			}
			if len(r.probes) >= 256 {
				break
			}
			r.probes[token] = pendingProbe{now, p}
			if err := r.write(Probe, token[:], p.local, p.endpoint, &out); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}
func (r *Receiver) updateReorderBudget() {
	count := 0
	minimum, maximum, jitter := math.Inf(1), 0., 0.
	for _, p := range r.paths {
		if p.ready && p.hasRTT {
			count++
			minimum = math.Min(minimum, p.rtt)
			maximum = math.Max(maximum, p.rtt)
			jitter = math.Max(jitter, p.jitter)
		}
	}
	timeout := r.reorderBase.Seconds()
	if count >= 2 {
		timeout = math.Min(.2, math.Max(timeout, math.Max((maximum-minimum)/2, maximum/2)+4*jitter+timeout))
	}
	r.reorder.config.Timeout = time.Duration(timeout * float64(time.Second))
}
