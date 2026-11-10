package main

import (
	"context"
	"sync"
	"time"

	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/dishwatch"
)

// dishConfig points the client at a Starlink dish serving one uplink.
type dishConfig struct {
	URL         string `json:"url"`
	UplinkIndex int    `json:"uplink_index"`
	IntervalMS  int    `json:"interval_ms"`
}

var dishStatus struct {
	sync.Mutex
	on                         bool
	uplink                     int
	last                       dishwatch.Sample
	polls, failures, hintCount uint64
	hinted                     bool
}

const dishHintTTL = 4 * time.Second

// startDishWatch feeds the dish's own per-second loss and latency to the
// sender, which then steers bulk off that uplink and raises redundancy while
// the dish reports trouble. An unreachable dish is simply not a signal.
func startDishWatch(ctx context.Context, cfg *dishConfig, c *client.Client) {
	if cfg == nil || cfg.URL == "" {
		return
	}
	dishStatus.Lock()
	dishStatus.on, dishStatus.uplink = true, cfg.UplinkIndex
	dishStatus.Unlock()
	go dishwatch.Run(ctx, dishwatch.Config{URL: cfg.URL, Interval: time.Duration(cfg.IntervalMS) * time.Millisecond}, func(s dishwatch.Sample) {
		dishStatus.Lock()
		dishStatus.polls++
		if !s.OK {
			dishStatus.failures++
		} else {
			dishStatus.last = s
		}
		if s.OK && s.Degraded && !dishStatus.hinted {
			dishStatus.hintCount++
		}
		dishStatus.hinted = s.OK && s.Degraded
		dishStatus.Unlock()
		if s.OK {
			c.SetPathHint(cfg.UplinkIndex, s.Degraded, dishHintTTL, s.Reason)
		}
	})
}

func dishStatusDoc() any {
	dishStatus.Lock()
	defer dishStatus.Unlock()
	if !dishStatus.on {
		return nil
	}
	s := dishStatus.last
	return map[string]any{"uplink": dishStatus.uplink, "polls": dishStatus.polls, "failures": dishStatus.failures,
		"hint_events": dishStatus.hintCount, "degraded": dishStatus.hinted, "reason": s.Reason,
		"drop_max_3s": s.DropMax3s, "latency_ms": s.LatencyMS, "baseline_ms": s.BaseMS}
}
