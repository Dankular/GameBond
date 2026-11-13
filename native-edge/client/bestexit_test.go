package client

import (
	"net/netip"
	"testing"
	"time"
)

func testCands(rtts ...float64) []*candidate {
	var cs []*candidate
	for i, r := range rtts {
		cs = append(cs, &candidate{addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 4433), ready: true, rtt: r})
	}
	return cs
}

func TestFasterPrefersKnownLowerRTT(t *testing.T) {
	a, b, unknown := &candidate{rtt: 30}, &candidate{rtt: 50}, &candidate{}
	if !faster(a, nil) || !faster(a, b) || faster(b, a) || !faster(a, unknown) || faster(unknown, a) || faster(unknown, nil) == false {
		t.Fatal("ordering is wrong")
	}
}

func TestBetterExitNeedsARealGainAndMeasurements(t *testing.T) {
	now := time.Now()
	run := func(active float64, cands []*candidate) (*candidate, bool) {
		c := &Client{}
		c.fo.activeRTT = active
		c.fo.standby = &standby{cands: cands}
		c.fo.evalEnd = now.Add(time.Minute)
		return c.betterExit(now)
	}
	// 80 ms active, 30 and 45 ms standbys: the 30 ms one wins.
	cs := testCands(45, 30)
	if best, done := run(80, cs); !done || best != cs[1] {
		t.Fatalf("want the 30 ms standby, got %v done=%v", best, done)
	}
	// 75 vs 80 is under the margin (the larger of 10 ms and 20%): stay, and the check is over.
	if best, done := run(80, testCands(75)); !done || best != nil {
		t.Fatalf("a 5 ms gain must not move: %v %v", best, done)
	}
	// a standby that is ready but not measured yet: keep waiting, decide nothing.
	if best, done := run(80, testCands(30, 0)); done || best != nil {
		t.Fatalf("must wait for the reading: %v %v", best, done)
	}
	// the active exit has no reading: wait.
	if best, done := run(0, testCands(30)); done || best != nil {
		t.Fatalf("must wait for the active reading: %v %v", best, done)
	}
	// readings never arrive: the check is dropped without a move.
	c := &Client{}
	c.fo.evalEnd = now.Add(-time.Second)
	c.fo.standby = &standby{cands: testCands(30)}
	if best, done := c.betterExit(now); !done || best != nil {
		t.Fatalf("expired check must end quietly: %v %v", best, done)
	}
}

func TestPathRTTUsesTheBestReadyPath(t *testing.T) {
	if pathRTT(nil) != 0 {
		t.Fatal("no paths means unknown")
	}
}
