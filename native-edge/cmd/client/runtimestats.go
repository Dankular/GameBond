package main

import (
	"math"
	"runtime"
	"runtime/metrics"
)

var runtimeSamples = []metrics.Sample{
	{Name: "/gc/pauses:seconds"},
	{Name: "/sched/latencies:seconds"},
	{Name: "/gc/cycles/total:gc-cycles"},
	{Name: "/gc/heap/allocs:bytes"},
	{Name: "/memory/classes/heap/objects:bytes"},
}

// histogramOver returns how many observations fell in buckets whose lower bound is at
// least minSeconds, and the upper bound of the highest non-empty bucket (seconds).
func histogramOver(h *metrics.Float64Histogram, minSeconds float64) (count uint64, maxSeconds float64) {
	for i, c := range h.Counts {
		if c == 0 {
			continue
		}
		if h.Buckets[i] >= minSeconds {
			count += c
		}
		if up := h.Buckets[i+1]; !math.IsInf(up, 1) {
			maxSeconds = up
		} else {
			maxSeconds = h.Buckets[i]
		}
	}
	return
}

// runtimeStats reports the Go runtime's own view of stalls: stop-the-world GC pauses and
// the time runnable goroutines waited for a thread. They explain an engine-loop stall
// that the network cannot.
func runtimeStats() map[string]any {
	metrics.Read(runtimeSamples)
	out := map[string]any{"goroutines": runtime.NumGoroutine(), "gomaxprocs": runtime.GOMAXPROCS(0)}
	if v := runtimeSamples[0].Value; v.Kind() == metrics.KindFloat64Histogram {
		over1, max := histogramOver(v.Float64Histogram(), .001)
		over5, _ := histogramOver(v.Float64Histogram(), .005)
		out["gc_pause_over_1ms"], out["gc_pause_over_5ms"], out["gc_pause_max_ms"] = over1, over5, max*1000
	}
	if v := runtimeSamples[1].Value; v.Kind() == metrics.KindFloat64Histogram {
		over1, max := histogramOver(v.Float64Histogram(), .001)
		over10, _ := histogramOver(v.Float64Histogram(), .010)
		out["sched_wait_over_1ms"], out["sched_wait_over_10ms"], out["sched_wait_max_ms"] = over1, over10, max*1000
	}
	if v := runtimeSamples[2].Value; v.Kind() == metrics.KindUint64 {
		out["gc_cycles"] = v.Uint64()
	}
	if v := runtimeSamples[3].Value; v.Kind() == metrics.KindUint64 {
		out["alloc_bytes_total"] = v.Uint64()
	}
	if v := runtimeSamples[4].Value; v.Kind() == metrics.KindUint64 {
		out["heap_live_bytes"] = v.Uint64()
	}
	return out
}
