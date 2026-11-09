package bond

import (
	"encoding/binary"
	"math"
	"time"
)

// Failover replay mirrors Python's failover_replay. A ready path that has been
// silent for longer than suspectAfter is "suspect": bulk traffic avoids it while
// another path is alive, and the packets it carried since just before it went
// quiet are replayed on the best live path. Replays reuse the original flow and
// sequence number, so the receiver keeps whichever copy arrives first.

const (
	failoverCacheLimit = 512 // packets queued per suspect transition
	failoverPerTick    = 16  // replays sent per Maintenance call
	failoverPathLimit  = 1.5 // seconds; half of the 3s eligibility timeout
)

type replayItem struct{ key MissingPacket }

// EnableFailover turns on suspect-path tracking and replay. Off by default.
func (s *Sender) EnableFailover(on bool) { s.failover = on }

func (s *Sender) suspectAfter(p *receivePath) time.Duration {
	probe := s.r.probeInterval.Seconds()
	after := math.Max(2.5*probe, 4*p.rtt+8*p.jitter)
	return time.Duration(math.Min(failoverPathLimit, after) * float64(time.Second))
}

func (s *Sender) pathSuspect(p *receivePath, now time.Time) bool {
	return p.ready && now.Sub(p.last) >= s.suspectAfter(p)
}

// failoverStep updates suspect state, queues replays on a new suspicion, and
// sends a bounded number of queued replays on the best live path.
func (s *Sender) failoverStep(now time.Time, writer DatagramWriter) error {
	var live []*receivePath
	for _, p := range s.eligible(now, true) {
		if !s.pathSuspect(p, now) {
			live = append(live, p)
		}
	}
	for _, p := range s.r.paths {
		if !p.ready {
			p.suspect = false
			continue
		}
		suspect := s.pathSuspect(p, now)
		switch {
		case suspect && !p.suspect:
			p.suspect = true
			s.stats.FailoverSuspected++
			s.queueReplays(p)
		case !suspect && p.suspect:
			p.suspect = false
			s.stats.FailoverRecovered++
		}
	}
	timestamp := s.r.seconds(now)
	for sent := 0; sent < failoverPerTick && len(s.replayQueue) > 0; {
		item := s.replayQueue[0]
		cached := s.repairs[item.key]
		if cached == nil {
			s.replayQueue = s.replayQueue[1:]
			s.stats.FailoverReplayDropped++
			continue
		}
		size := len(cached.payload) + Overhead + 24
		var target *receivePath
		bestScore := math.Inf(1)
		for _, p := range s.fitPaths(live, size) {
			ready, err := p.budget.ReadyAt(size, timestamp)
			if err != nil {
				return err
			}
			if math.Max(ready, p.pacer.ReadyAt(size+28, timestamp)) > timestamp+.000001 {
				continue
			}
			probe := 0.
			if p.hasRTT {
				probe = p.rtt
			}
			if score := ready + p.budget.TransitSeconds(size, probe); score < bestScore {
				bestScore, target = score, p
			}
		}
		if target == nil {
			if len(live) == 0 {
				// Nothing to replay on: drop rather than hold stale packets.
				s.stats.FailoverReplayDropped += uint64(len(s.replayQueue))
				s.replayQueue = nil
			}
			break
		}
		body := make([]byte, 24+len(cached.payload))
		binary.BigEndian.PutUint64(body, item.key.Flow)
		binary.BigEndian.PutUint64(body[8:], item.key.Number)
		binary.BigEndian.PutUint64(body[16:], target.txEpoch)
		copy(body[24:], cached.payload)
		frame, err := s.r.codec.Encode(Striped, body)
		if err != nil {
			return err
		}
		if !s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local}, target, now, writer) {
			break
		}
		target.budget.Sent(binary.BigEndian.Uint64(frame[37:]), len(frame), timestamp)
		cached.origin = target
		s.replayQueue = s.replayQueue[1:]
		s.stats.FailoverReplayed++
		s.stats.Copies++
		sent++
	}
	return nil
}

// queueReplays queues the cached packets p carried since just before it went
// quiet, oldest first, at most failoverCacheLimit.
func (s *Sender) queueReplays(p *receivePath) {
	since := p.last.Add(-time.Duration(p.rtt * float64(time.Second)))
	var picked []MissingPacket
	for e := s.repairOrder.Back(); e != nil && len(picked) < failoverCacheLimit; e = e.Prev() {
		entry := e.Value.(*repairEntry)
		if entry.origin == p && !entry.at.Before(since) {
			picked = append(picked, entry.key)
		}
	}
	for i := len(picked) - 1; i >= 0; i-- {
		s.replayQueue = append(s.replayQueue, replayItem{picked[i]})
	}
}
