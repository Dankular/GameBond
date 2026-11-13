package main

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"gamebond.local/nativeedge/slo"
)

func TestSLOStatusSurvivesInfiniteQuantiles(t *testing.T) {
	r, err := newSLO(sloOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r.prober = slo.NewProber(slo.ProbeConfig{}, r.tracker)
	r.eval.Store(&slo.Evaluation{At: time.Now(), Windows: []slo.WindowResult{{Window: time.Hour, P99: math.Inf(1), Delivery: slo.Indicator{Ratio: 1, BurnRate: math.NaN()}}}})
	b, err := json.Marshal(r.status())
	if err != nil {
		t.Fatalf("status is not JSON-safe: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil || back["evaluation"] == nil {
		t.Fatalf("round trip: %v %v", err, back)
	}
}

func TestMetricsAddrMustBeLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:9477": true, "[::1]:9477": true, "0.0.0.0:9477": false, "192.168.1.5:9477": false, "nonsense": false} {
		if (loopbackAddr(addr) == nil) != ok {
			t.Errorf("%s: want ok=%v", addr, ok)
		}
	}
}
