package main

import (
	"container/heap"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// Impair describes what one direction of one emulated link does to packets. A zero value is a clean
// link.
type Impair struct {
	Down        bool          // cable pulled: everything is dropped, queued packets included
	Loss        float64       // independent random loss, 0..1
	BurstGood   float64       // Gilbert-Elliott: chance per packet of entering the bad state
	BurstBad    float64       // ... and of leaving it; both must be > 0 for burst loss (bad drops everything)
	Delay       time.Duration // added one-way latency
	Jitter      time.Duration // plus up to this much, order preserved
	RateBps     float64       // 0 = unlimited; otherwise a serialising bottleneck with a bounded queue
	QueueBudget time.Duration // longest the bottleneck queue may hold a packet before tail drop (default 250 ms)
}

type held struct {
	at  time.Time
	seq uint64
	pkt []byte
}

type heldHeap []held

func (h heldHeap) Len() int { return len(h) }
func (h heldHeap) Less(i, j int) bool {
	if h[i].at.Equal(h[j].at) {
		return h[i].seq < h[j].seq
	}
	return h[i].at.Before(h[j].at)
}
func (h heldHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *heldHeap) Push(x any)   { *h = append(*h, x.(held)) }
func (h *heldHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// shaper applies an Impair to a stream of packets and hands the survivors to out.
type shaper struct {
	cfg atomic.Pointer[Impair]
	out func([]byte)

	mu       sync.Mutex
	rng      *rand.Rand
	bad      bool
	nextFree time.Time
	lastRel  time.Time
	seq      uint64
	q        heldHeap
	wake     chan struct{}

	In, Dropped, Out atomic.Uint64
}

func newShaper(seed int64, out func([]byte)) *shaper {
	s := &shaper{out: out, rng: rand.New(rand.NewSource(seed)), wake: make(chan struct{}, 1)}
	s.cfg.Store(&Impair{})
	return s
}

func (s *shaper) Set(c Impair) { s.cfg.Store(&c) }

// Push takes ownership of pkt.
func (s *shaper) Push(pkt []byte) {
	s.In.Add(1)
	c := s.cfg.Load()
	if c.Down {
		s.Dropped.Add(1)
		return
	}
	now := time.Now()
	s.mu.Lock()
	if c.BurstGood > 0 && c.BurstBad > 0 {
		if s.bad {
			if s.rng.Float64() < c.BurstBad {
				s.bad = false
			}
		} else if s.rng.Float64() < c.BurstGood {
			s.bad = true
		}
		if s.bad {
			s.mu.Unlock()
			s.Dropped.Add(1)
			return
		}
	}
	if c.Loss > 0 && s.rng.Float64() < c.Loss {
		s.mu.Unlock()
		s.Dropped.Add(1)
		return
	}
	rel := now
	if c.RateBps > 0 {
		budget := c.QueueBudget
		if budget <= 0 {
			budget = 250 * time.Millisecond
		}
		start := s.nextFree
		if start.Before(now) {
			start = now
		}
		done := start.Add(time.Duration(float64(len(pkt)*8) / c.RateBps * float64(time.Second)))
		if done.Sub(now) > budget {
			s.mu.Unlock()
			s.Dropped.Add(1)
			return
		}
		s.nextFree = done
		rel = done
	}
	rel = rel.Add(c.Delay)
	if c.Jitter > 0 {
		rel = rel.Add(time.Duration(s.rng.Int63n(int64(c.Jitter))))
	}
	if rel.Before(s.lastRel) {
		rel = s.lastRel // a link does not reorder; jitter only stretches gaps
	}
	s.lastRel = rel
	if c.Delay == 0 && c.Jitter == 0 && c.RateBps == 0 && len(s.q) == 0 {
		s.mu.Unlock()
		s.Out.Add(1)
		s.out(pkt)
		return
	}
	s.seq++
	heap.Push(&s.q, held{at: rel, seq: s.seq, pkt: pkt})
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// run releases held packets when they are due.
func (s *shaper) run(done <-chan struct{}) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		s.mu.Lock()
		var wait time.Duration = time.Hour
		for len(s.q) > 0 {
			top := s.q[0]
			if d := time.Until(top.at); d > 0 {
				wait = d
				break
			}
			heap.Pop(&s.q)
			s.mu.Unlock()
			if s.cfg.Load().Down {
				s.Dropped.Add(1)
			} else {
				s.Out.Add(1)
				s.out(top.pkt)
			}
			s.mu.Lock()
		}
		s.mu.Unlock()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-done:
			return
		case <-s.wake:
		case <-timer.C:
		}
	}
}
