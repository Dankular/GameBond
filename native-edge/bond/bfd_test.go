package bond

import (
	"testing"
	"time"
)

func TestBFDDetectsOneWayFailureAndHoldsDown(t *testing.T) {
	r := &Receiver{}
	p := &receivePath{}
	t0 := time.Unix(1000, 0)
	frame := func(hears byte) []byte { return []byte{hears, bfdMultiplier, 100, 0, 0, 0, 0, 0} }

	r.bfdReceived(p, frame(1), t0)
	if !p.bfd.up || p.bfdDown() {
		t.Fatal("first healthy exchange must come up without hold-down")
	}
	// Peer stops hearing us: down at once, though frames still arrive.
	r.bfdReceived(p, frame(0), t0.Add(100*time.Millisecond))
	if !p.bfdDown() {
		t.Fatal("peer-reported one-way loss not detected")
	}
	// Peer hears us again: hold-down keeps it down for bfdHoldDown.
	for i := 2; i < 12; i++ {
		r.bfdReceived(p, frame(1), t0.Add(time.Duration(i)*100*time.Millisecond))
	}
	if !p.bfdDown() {
		t.Fatal("path returned before hold-down")
	}
	for i := 12; i < 25; i++ {
		r.bfdReceived(p, frame(1), t0.Add(time.Duration(i)*100*time.Millisecond))
	}
	if p.bfdDown() {
		t.Fatal("path did not return after hold-down")
	}
	// Silence beyond the detect time: down.
	r.bfdEvaluate(p, t0.Add(2500*time.Millisecond+400*time.Millisecond))
	if !p.bfdDown() {
		t.Fatal("silence not detected within detect time")
	}
}
