package bond

import (
	"encoding/binary"
	"math"
	"time"
)

type protection int

const (
	protectNone protection = iota
	protectParity
	protectDuplicate
)

// lossEstimate is the path's smoothed delivery loss, or 0 when it has not been
// measured within lossStale seconds.
func (s *Sender) lossEstimate(p *receivePath, ts float64) float64 {
	if !p.budget.lossSeen || ts-p.budget.lossAt > lossStale {
		return 0
	}
	return p.budget.lossEWMA
}

// protectionLevel picks parity or duplication from the worst path, or from a
// degraded hint (the Starlink dish reporting drops).
func (s *Sender) protectionLevel(paths []*receivePath, now time.Time) protection {
	if len(paths) < 2 {
		return protectNone
	}
	ts := s.r.seconds(now)
	worst := 0.
	for _, p := range paths {
		worst = math.Max(worst, s.lossEstimate(p, ts))
		if s.hinted(p.local, now) {
			return protectDuplicate
		}
	}
	switch {
	case worst >= dupRatio:
		return protectDuplicate
	case worst >= fecRatio:
		return protectParity
	}
	return protectNone
}

// bulkProtect runs after a bulk packet was sent on used: it duplicates the packet
// on a second ready path or folds it into the flow's parity group.
func (s *Sender) bulkProtect(f *sendFlow, number uint64, payload []byte, used *receivePath, now time.Time, writer DatagramWriter) {
	paths := s.eligible(now, true)
	level := s.protectionLevel(paths, now)
	if level != protectParity {
		f.fecMask = 0
	}
	switch level {
	case protectDuplicate:
		s.duplicate(f, number, payload, used, paths, now, writer)
	case protectParity:
		s.accumulateParity(f, number, payload, used, paths, now, writer)
	}
}

// other returns the ready path (other than used) with the shortest transit time.
func (s *Sender) other(used *receivePath, paths []*receivePath, size int, now time.Time) *receivePath {
	ts := s.r.seconds(now)
	var best *receivePath
	bestScore := math.Inf(1)
	for _, p := range s.fitPaths(paths, size) {
		if p == used {
			continue
		}
		ready, err := p.budget.ReadyAt(size, ts)
		if err != nil || math.Max(ready, p.pacer.ReadyAt(size+28, ts)) > ts+.000001 {
			continue
		}
		probe := 0.
		if p.hasRTT {
			probe = p.rtt
		}
		if score := p.budget.TransitSeconds(size, probe); score < bestScore {
			best, bestScore = p, score
		}
	}
	return best
}

func (s *Sender) duplicate(f *sendFlow, number uint64, payload []byte, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) {
	size := len(payload) + Overhead + 24
	target := s.other(used, paths, size, now)
	if target == nil {
		return
	}
	body := make([]byte, 24+len(payload))
	binary.BigEndian.PutUint64(body, f.id)
	binary.BigEndian.PutUint64(body[8:], number)
	binary.BigEndian.PutUint64(body[16:], target.txEpoch)
	copy(body[24:], payload)
	frame, err := s.r.codec.Encode(Striped, body)
	if err != nil {
		return
	}
	if s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local}, target, now, writer) {
		target.budget.Sent(binary.BigEndian.Uint64(frame[37:]), len(frame), s.r.seconds(now))
		s.stats.Copies++
		s.stats.BulkDuplicates++
	}
}

// accumulateParity folds the packet into the flow's current group and emits the
// parity frame when the group is complete or the flow moved to the next group.
func (s *Sender) accumulateParity(f *sendFlow, number uint64, payload []byte, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) {
	base := number - number%fecK
	if f.fecMask != 0 && f.fecBase != base {
		s.emitParity(f, used, paths, now, writer)
	}
	if f.fecMask == 0 {
		f.fecBase, f.fecXor = base, f.fecXor[:0]
	}
	if need := 2 + len(payload); need > len(f.fecXor) {
		f.fecXor = append(f.fecXor, make([]byte, need-len(f.fecXor))...)
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	f.fecXor[0] ^= l[0]
	f.fecXor[1] ^= l[1]
	for i, b := range payload {
		f.fecXor[2+i] ^= b
	}
	f.fecMask |= 1 << (number - base)
	if number%fecK == fecK-1 {
		s.emitParity(f, used, paths, now, writer)
	}
}

func (s *Sender) emitParity(f *sendFlow, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) {
	if f.fecMask == 0 {
		return
	}
	body := make([]byte, parityHeader+len(f.fecXor))
	binary.BigEndian.PutUint64(body, f.id)
	binary.BigEndian.PutUint64(body[8:], f.fecBase)
	body[16] = f.fecMask
	copy(body[parityHeader:], f.fecXor)
	f.fecMask, f.fecXor = 0, f.fecXor[:0]
	size := len(body) + Overhead
	// Parity travels on a different path than the data when one is ready, so a
	// single-path loss burst cannot take both.
	target := s.other(used, paths, size, now)
	if target == nil {
		target = used
	}
	frame, err := s.r.codec.Encode(Parity, body)
	if err != nil {
		return
	}
	if s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local}, target, now, writer) {
		s.stats.Copies++
		s.stats.ParitySent++
	}
}

// lossSteered applies the steering hysteresis to one path.
func (s *Sender) lossSteered(p *receivePath, ts float64) bool {
	est := s.lossEstimate(p, ts)
	if p.steerOn {
		if ts >= p.steerUntil && est < lossSteerExit {
			p.steerOn = false
		}
	} else if est >= lossSteerRatio {
		p.steerOn, p.steerUntil = true, ts+lossSteerHold
		s.stats.LossSteered++
	}
	return p.steerOn
}
