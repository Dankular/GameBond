package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"gamebond.local/nativeedge/client"
)

type fault struct {
	class  string
	link   int // -1: several or none
	dur    [2]time.Duration
	detail string
	apply  func() (undo func(), skip string)
}

type scheduler struct {
	ctx    context.Context
	net    *emuNet
	c      *client.Client
	st     *stats
	links  int
	backup bool
	quick  bool
	rng    *rand.Rand
	log    func(map[string]any)
	n      int
}

func sec(a, b float64) [2]time.Duration {
	return [2]time.Duration{time.Duration(a * float64(time.Second)), time.Duration(b * float64(time.Second))}
}

// catalogue lists every fault class. Each runs once per link where it is link-specific.
func (s *scheduler) catalogue() []fault {
	var fs []fault
	linkFault := func(class string, l int, dur [2]time.Duration, detail string, imp Impair) fault {
		return fault{class: class, link: l, dur: dur, detail: detail, apply: func() (func(), string) {
			s.net.setLink(l, imp)
			return func() { s.net.setLink(l, Impair{}) }, ""
		}}
	}
	bothFault := func(class string, dur [2]time.Duration, detail string, imp Impair) fault {
		return fault{class: class, link: -1, dur: dur, detail: detail, apply: func() (func(), string) {
			for l := 0; l < s.links; l++ {
				s.net.setLink(l, imp)
			}
			return func() {
				for l := 0; l < s.links; l++ {
					s.net.setLink(l, Impair{})
				}
			}, ""
		}}
	}
	burst := Impair{BurstGood: 0.02, BurstBad: 0.25} // about 7% loss in bursts of about 4 packets
	for l := 0; l < s.links; l++ {
		fs = append(fs,
			linkFault("link-pull", l, sec(10, 40), "link cut", Impair{Down: true}),
			linkFault("throttle-256k", l, sec(40, 50), "256 kbit/s, 250 ms queue", Impair{RateBps: 256e3}),
			linkFault("throttle-1m", l, sec(40, 50), "1 Mbit/s, 250 ms queue", Impair{RateBps: 1e6}),
			linkFault("burst-loss", l, sec(35, 45), "Gilbert-Elliott, about 7% in bursts", burst),
			linkFault("random-loss-5pct", l, sec(35, 45), "5% independent loss", Impair{Loss: 0.05}),
			linkFault("latency-200ms", l, sec(25, 35), "+200 ms, 30 ms jitter", Impair{Delay: 200 * time.Millisecond, Jitter: 30 * time.Millisecond}),
		)
	}
	if s.links > 1 {
		fs = append(fs,
			bothFault("burst-loss-all-links", sec(25, 35), "burst loss on every link at once", burst),
			bothFault("total-outage", sec(6, 10), "every link cut", Impair{Down: true}),
		)
	}
	if s.backup {
		fs = append(fs, fault{class: "exit-blackhole", link: -1, dur: sec(20, 30), detail: "the active exit server stops answering", apply: func() (func(), string) {
			deadline := time.Now().Add(60 * time.Second)
			for {
				ex := s.c.Snapshot().Exit
				idx := s.net.exitIndex(ex.Active)
				ready := false
				for _, sv := range ex.Servers {
					if !sv.Active && sv.State == "reachable" {
						ready = true
					}
				}
				if idx >= 0 && ready {
					e := s.net.exits[idx]
					e.blackhole.Store(true)
					return func() { e.blackhole.Store(false) }, ""
				}
				if time.Now().After(deadline) || s.ctx.Err() != nil {
					return nil, "no standby exit was reachable"
				}
				time.Sleep(500 * time.Millisecond)
			}
		}})
	}
	return fs
}

func (s *scheduler) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *scheduler) between(r [2]time.Duration) time.Duration {
	return r[0] + time.Duration(s.rng.Int63n(int64(r[1]-r[0])+1))
}

func (s *scheduler) run() {
	cat := s.catalogue()
	idle := sec(45, 90)
	if s.quick {
		idle = sec(4, 8)
	}
	for s.ctx.Err() == nil {
		s.rng.Shuffle(len(cat), func(i, j int) { cat[i], cat[j] = cat[j], cat[i] })
		for _, f := range cat {
			if !s.sleep(s.between(idle)) {
				return
			}
			d := s.between(f.dur)
			if s.quick {
				d = max(d/6, 3*time.Second)
			}
			if dl, ok := s.ctx.Deadline(); ok && time.Until(dl) < d+15*time.Second {
				return // not enough time left to inject and observe recovery
			}
			s.n++
			w := &window{ID: s.n, Class: f.class, Link: f.link, Detail: fmt.Sprintf("%s for %v", f.detail, d.Round(time.Second)), Start: time.Now()}
			undo, skip := f.apply()
			if skip != "" {
				w.Skipped = skip
				s.st.begin(w)
				s.log(map[string]any{"event": "fault-skipped", "id": w.ID, "class": w.Class, "why": skip})
				continue
			}
			s.st.begin(w)
			s.log(map[string]any{"event": "fault-start", "id": w.ID, "class": w.Class, "link": w.Link, "detail": w.Detail})
			ok := s.sleep(d)
			undo()
			s.st.finish(w, time.Now())
			s.log(map[string]any{"event": "fault-end", "id": w.ID, "class": w.Class})
			if !ok {
				return
			}
			s.sleep(8 * time.Second) // recovery is observed before the next fault starts
		}
	}
}
