package hrclock

import (
	"testing"
	"time"
)

func TestNowAdvancesFinerThanAMillisecondAndNeverGoesBack(t *testing.T) {
	last := Now()
	distinct := 0
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		n := Now()
		if n.Before(last) {
			t.Fatalf("clock went backwards: %v < %v", n, last)
		}
		if n != last {
			distinct++
			last = n
		}
	}
	// At 1 ms granularity this would be about 100 readings in 100 ms.
	if distinct < 5000 {
		t.Fatalf("only %d distinct readings in 100 ms: resolution is too coarse", distinct)
	}
	if d := time.Since(Now()); d < -50*time.Millisecond || d > 50*time.Millisecond {
		t.Fatalf("drifted %v from the wall clock", d)
	}
}
