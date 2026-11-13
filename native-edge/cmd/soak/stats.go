package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/slo"
)

const nHist = 12 // len(slo.BucketsMS)+1

type counts struct {
	Sent, Recv, Lost, Late uint64
	Hist                   [nHist]uint64
}

func (c *counts) add(o counts) {
	c.Sent += o.Sent
	c.Recv += o.Recv
	c.Lost += o.Lost
	c.Late += o.Late
	for i := range c.Hist {
		c.Hist[i] += o.Hist[i]
	}
}

// pctile is the upper edge of the histogram bucket holding quantile q (the top bucket is +Inf).
func (c counts) pctile(q float64) float64 {
	var n uint64
	for _, h := range c.Hist {
		n += h
	}
	if n == 0 {
		return 0
	}
	target := uint64(math.Ceil(q * float64(n)))
	var cum uint64
	for i, h := range c.Hist {
		cum += h
		if cum >= target {
			if i < len(slo.BucketsMS) {
				return slo.BucketsMS[i]
			}
			return math.Inf(1)
		}
	}
	return math.Inf(1)
}

// wilsonUpper is the 95% upper confidence bound of a loss ratio; at zero loss it is about 3/n.
func wilsonUpper(k, n uint64) float64 {
	if n == 0 {
		return 1
	}
	const z = 1.959964
	p, nn := float64(k)/float64(n), float64(n)
	d := 1 + z*z/nn
	return (p + z*z/(2*nn) + z*math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn))) / d
}

// window is one injected fault.
type window struct {
	ID         int       `json:"id"`
	Class      string    `json:"class"`
	Link       int       `json:"link"` // -1 when not tied to one link
	Detail     string    `json:"detail"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"` // zero while active
	Skipped    string    `json:"skipped,omitempty"`
	Counts     map[string]*counts `json:"probes"`
	BlackoutMS float64   `json:"blackout_ms"` // longest run with no answered game probe during the fault
	RecoverMS  float64   `json:"recover_after_clear_ms"`
}

type gap struct {
	From, To time.Time
}

func (g gap) dur() time.Duration { return g.To.Sub(g.From) }

type stats struct {
	mu       sync.Mutex
	interval time.Duration // game probe interval; a gap is a silence longer than 3x this
	margin   time.Duration // a fault's effects are charged to it this long after it is lifted
	windows  []*window
	by       map[string]map[string]*counts // stream -> class -> counts
	gaps     []gap
	lastRecv time.Time
}

func newStats(interval time.Duration) *stats {
	return &stats{interval: interval, margin: 4 * time.Second, by: map[string]map[string]*counts{}}
}

// classify returns the fault a probe sent at t belongs to (nil: clean). Caller holds mu.
func (s *stats) classify(t time.Time) *window {
	for i := len(s.windows) - 1; i >= 0 && i >= len(s.windows)-3; i-- {
		w := s.windows[i]
		if w.Skipped != "" {
			continue
		}
		end := w.End
		if end.IsZero() {
			end = t
		} else {
			end = end.Add(s.margin)
		}
		if !t.Before(w.Start) && !t.After(end) {
			return w
		}
	}
	return nil
}

func (s *stats) cell(stream string, w *window) (*counts, *counts) {
	class := "clean"
	if w != nil {
		class = w.Class
	}
	m := s.by[stream]
	if m == nil {
		m = map[string]*counts{}
		s.by[stream] = m
	}
	c := m[class]
	if c == nil {
		c = &counts{}
		m[class] = c
	}
	var wc *counts
	if w != nil {
		if w.Counts == nil {
			w.Counts = map[string]*counts{}
		}
		if wc = w.Counts[stream]; wc == nil {
			wc = &counts{}
			w.Counts[stream] = wc
		}
	}
	return c, wc
}

func (s *stats) each(stream string, t time.Time, f func(*counts)) {
	s.mu.Lock()
	c, wc := s.cell(stream, s.classify(t))
	f(c)
	if wc != nil {
		f(wc)
	}
	s.mu.Unlock()
}

func bucketOf(rtt time.Duration) int {
	ms := float64(rtt) / float64(time.Millisecond)
	for i, b := range slo.BucketsMS {
		if ms <= b {
			return i
		}
	}
	return len(slo.BucketsMS)
}

// stream is a slo.Sink for one probe stream. Outcomes are charged to the fault active when the
// probe was sent. The game stream also feeds gap tracking and an optional second sink.
type stream struct {
	s     *stats
	name  string
	also  slo.Sink
	track bool
}

func (m stream) Sent(t time.Time) {
	m.s.each(m.name, t, func(c *counts) { c.Sent++ })
	if m.also != nil {
		m.also.Sent(t)
	}
}

func (m stream) Received(sent time.Time, rtt time.Duration) {
	b := bucketOf(rtt)
	m.s.each(m.name, sent, func(c *counts) { c.Recv++; c.Hist[b]++ })
	if m.track {
		m.s.mu.Lock()
		if sent.After(m.s.lastRecv) {
			if !m.s.lastRecv.IsZero() && sent.Sub(m.s.lastRecv) > 3*m.s.interval {
				m.s.gaps = append(m.s.gaps, gap{m.s.lastRecv, sent})
			}
			m.s.lastRecv = sent
		}
		m.s.mu.Unlock()
	}
	if m.also != nil {
		m.also.Received(sent, rtt)
	}
}

func (m stream) Lost(t time.Time) {
	m.s.each(m.name, t, func(c *counts) { c.Lost++ })
	if m.also != nil {
		m.also.Lost(t)
	}
}

func (m stream) Late(t time.Time, rtt time.Duration) {
	m.s.each(m.name, t, func(c *counts) { c.Late++ })
	if m.also != nil {
		m.also.Late(t, rtt)
	}
}

func (s *stats) begin(w *window) {
	s.mu.Lock()
	s.windows = append(s.windows, w)
	s.mu.Unlock()
}

func (s *stats) finish(w *window, now time.Time) {
	s.mu.Lock()
	w.End = now
	s.mu.Unlock()
}

// settle computes each finished fault's blackout from the gaps seen, and returns the gaps that fell
// outside every fault. Call it when the run is quiet (the report does).
func (s *stats) settle(now time.Time) (unexplained []gap) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.windows {
		w.BlackoutMS, w.RecoverMS = 0, 0
	}
	for _, g := range s.gaps {
		owner := (*window)(nil)
		for _, w := range s.windows {
			if w.Skipped != "" {
				continue
			}
			end := w.End
			if end.IsZero() {
				end = now
			}
			end = end.Add(s.margin + 2*time.Second)
			if !g.From.After(end) && !g.To.Before(w.Start.Add(-time.Second)) {
				owner = w
				break
			}
		}
		if owner == nil {
			unexplained = append(unexplained, g)
			continue
		}
		if ms := float64(g.dur()) / float64(time.Millisecond); ms > owner.BlackoutMS {
			owner.BlackoutMS = ms
		}
		if !owner.End.IsZero() && g.To.After(owner.End) {
			if ms := float64(g.To.Sub(owner.End)) / float64(time.Millisecond); ms > owner.RecoverMS {
				owner.RecoverMS = ms
			}
		}
	}
	return unexplained
}

func pct(r float64) string {
	switch {
	case r == 0:
		return "0"
	case r < 1e-6:
		return fmt.Sprintf("%.1e%%", r*100)
	}
	return fmt.Sprintf("%.4f%%", r*100)
}

func ms(v float64) string {
	if math.IsInf(v, 1) {
		return ">1000 ms"
	}
	return fmt.Sprintf("%.0f ms", v)
}

func quantile(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	i := int(math.Ceil(q*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	return s[i]
}

// classTable renders one stream's loss and the blackout per fault class.
func (s *stats) classTable(stream string, withBlackout bool) string {
	m := s.by[stream]
	var classes []string
	for c := range m {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool {
		if classes[i] == "clean" || classes[j] == "clean" {
			return classes[i] == "clean"
		}
		return classes[i] < classes[j]
	})
	var b strings.Builder
	if withBlackout {
		b.WriteString("| class | faults | probes sent | lost | loss | loss 95% upper | RTT p50 | RTT p99 | blackout median | blackout p95 | blackout max |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	} else {
		b.WriteString("| class | faults | probes sent | lost | loss | loss 95% upper | RTT p50 | RTT p99 |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
	}
	for _, class := range classes {
		c := m[class]
		var bl []float64
		n := 0
		for _, w := range s.windows {
			if w.Class == class && w.Skipped == "" && !w.End.IsZero() {
				n++
				bl = append(bl, w.BlackoutMS)
			}
		}
		nf := fmt.Sprint(n)
		if class == "clean" {
			nf = "–"
		}
		row := fmt.Sprintf("| %s | %s | %d | %d | %s | %s | %s | %s |", class, nf, c.Sent, c.Lost, pct(ratio(c.Lost, c.Sent)), pct(wilsonUpper(c.Lost, c.Sent)), ms(c.pctile(.5)), ms(c.pctile(.99)))
		if withBlackout {
			if class == "clean" || n == 0 {
				row += " – | – | – |"
			} else {
				row += fmt.Sprintf(" %s | %s | %s |", ms(quantile(bl, .5)), ms(quantile(bl, .95)), ms(quantile(bl, 1)))
			}
		}
		b.WriteString(row + "\n")
	}
	return b.String()
}

func ratio(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func (s *stats) total(stream string) counts {
	var t counts
	for _, c := range s.by[stream] {
		t.add(*c)
	}
	return t
}
