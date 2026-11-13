package slo

import (
	"math"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamebond.local/nativeedge/store"
)

var cfg = ProbeConfig{Src: netip.MustParseAddr("10.77.0.2"), Dst: netip.MustParseAddr("10.77.0.1"), ID: 0x6b42, Size: 100, Timeout: time.Second}

func open(t *testing.T) *Tracker {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "slo.db"), []string{Schema})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewTracker(db)
}

func TestProbeRoundTripAndChecksums(t *testing.T) {
	tr := open(t)
	p := NewProber(cfg, tr)
	t0 := time.Unix(1_800_000_000, 0)
	req := p.Build(t0)
	if len(req) != 100 || checksum(req[:20]) != 0 || checksum(req[20:]) != 0 {
		t.Fatalf("request is malformed: len=%d", len(req))
	}
	rep := Reply(req)
	if checksum(rep[:20]) != 0 || checksum(rep[20:]) != 0 {
		t.Fatal("reply checksums are wrong")
	}
	if !p.Handle(rep, t0.Add(42*time.Millisecond)) {
		t.Fatal("own reply not recognised")
	}
	if got := tr.Totals(); got.Sent != 1 || got.Received != 1 || got.Lost != 0 || got.Hist[bucket(42*time.Millisecond)] != 1 {
		t.Fatalf("%+v", got)
	}
	other := append([]byte(nil), rep...)
	other[24], other[25] = 0, 1 // another ICMP identifier: not ours, left for the stack
	if p.Handle(other, t0) {
		t.Fatal("consumed a reply with a foreign identifier")
	}
	if p.Handle(req, t0) {
		t.Fatal("consumed an echo request")
	}
}

func TestLossLateAndSecondAccounting(t *testing.T) {
	tr := open(t)
	p := NewProber(cfg, tr)
	t0 := time.Unix(1_800_000_000, 0)
	// second 0: answered; second 1: nothing comes back (an outage second); one probe answers late
	a := p.Build(t0)
	p.Handle(Reply(a), t0.Add(30*time.Millisecond))
	b := p.Build(t0.Add(time.Second))
	_ = p.Build(t0.Add(time.Second + 100*time.Millisecond))
	p.Expire(t0.Add(3 * time.Second))
	p.Handle(Reply(b), t0.Add(3500*time.Millisecond)) // after the timeout: still lost, counted late
	if err := tr.Flush(t0.Add(10*time.Second), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	got := tr.Totals()
	if got.Sent != 3 || got.Received != 1 || got.Lost != 2 || got.Late != 1 || got.Seconds != 2 || got.BadSeconds != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestEvaluateReportsLossBurnAndFailovers(t *testing.T) {
	tr := open(t)
	p := NewProber(cfg, tr)
	start := time.Unix(1_800_000_000, 0).Truncate(time.Minute)
	// 10 simulated minutes at 20 probes/s; 12 probes are lost in minute 4 and the rest echo in 40 ms
	n := 0
	for s := 0; s < 600; s++ {
		for k := 0; k < 20; k++ {
			ts := start.Add(time.Duration(s)*time.Second + time.Duration(k)*50*time.Millisecond)
			pkt := p.Build(ts)
			n++
			if s/60 == 4 && s%60 == 10 && k < 12 {
				continue
			}
			p.Handle(Reply(pkt), ts.Add(40*time.Millisecond))
		}
		p.Expire(start.Add(time.Duration(s)*time.Second + 2*time.Second))
	}
	now := start.Add(12 * time.Minute)
	p.Expire(now)
	tr.Event(start.Add(5*time.Minute), "failover", "primary to backup", 1800*time.Millisecond)
	tr.Event(start.Add(8*time.Minute), "failover", "backup to primary", 2600*time.Millisecond)
	if err := tr.Flush(now, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	ev, err := Evaluate(tr.db, now, DefaultObjectives())
	if err != nil {
		t.Fatal(err)
	}
	w := ev.Windows[0] // one hour
	if w.Sent != uint64(n) || w.Lost != 12 {
		t.Fatalf("sent %d lost %d", w.Sent, w.Lost)
	}
	if want := 12.0 / float64(n); math.Abs(w.LossRatio-want) > 1e-12 {
		t.Fatalf("loss %g want %g", w.LossRatio, want)
	}
	if w.LossUpper95 <= w.LossRatio || w.Delivery.Met != (w.Delivery.Ratio >= 0.9999) {
		t.Fatalf("%+v", w)
	}
	if want := (12.0 / float64(n)) / (1 - 0.9999); math.Abs(w.Delivery.BurnRate-want) > 1e-9 {
		t.Fatalf("burn %g want %g", w.Delivery.BurnRate, want)
	}
	if w.Availability.Total != 600 || w.Availability.Good != 600 || w.P50 != 50 {
		t.Fatalf("availability %+v p50 %v", w.Availability, w.P50)
	}
	if !w.Latency.Met {
		t.Fatalf("latency: %+v", w.Latency)
	}
	if ev.Failovers.Count != 2 || ev.Failovers.Max != 2600*time.Millisecond || !ev.Failovers.Met {
		t.Fatalf("%+v", ev.Failovers)
	}
	md := ev.Markdown()
	for _, want := range []string{"Measured loss", "| 1.0 h |", "95% upper bound", "failover(s)", "Delivery error budget left"} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q:\n%s", want, md)
		}
	}
}

func TestZeroLossGivesAnUpperBoundNotZero(t *testing.T) {
	if got := wilsonUpper(0, 1_000_000); got < 2.5e-6 || got > 4e-6 {
		t.Fatalf("%g", got)
	}
	if got := wilsonUpper(0, 0); got != 1 {
		t.Fatalf("%g", got)
	}
}

func TestFlushIsAdditiveAcrossRepeatedFlushes(t *testing.T) {
	tr := open(t)
	t0 := time.Unix(1_800_000_000, 0)
	tr.Sent(t0)
	if err := tr.Flush(t0.Add(time.Second), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	tr.Sent(t0.Add(time.Second))
	tr.Received(t0.Add(time.Second), 10*time.Millisecond)
	if err := tr.Flush(t0.Add(2*time.Second), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tr.Flush(t0.Add(3*time.Second), 3*time.Second); err != nil { // nothing new: must not double
		t.Fatal(err)
	}
	var sent, recv uint64
	if err := tr.db.QueryRow(`SELECT SUM(sent),SUM(recv) FROM slo_minute`).Scan(&sent, &recv); err != nil || sent != 2 || recv != 1 {
		t.Fatalf("%d %d %v", sent, recv, err)
	}
}
