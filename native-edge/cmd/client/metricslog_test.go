package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/client"
)

func TestMetricsLogRecordsPathsAndRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	m := newMetricsLog(path)
	snap := client.Snapshot{Ready: 2, Paths: []bond.PathSnapshot{
		{Local: 0, Ready: true, RTTMilliseconds: 50, Budget: map[string]any{"rate_mbps": 100.0, "ignored": 1}, BFD: map[string]any{"state": "up", "downs": 0}},
		{Local: 1, Ready: true, RTTMilliseconds: 53, Budget: map[string]any{"rate_mbps": 90.0}},
	}, QoS: map[string]any{"path_quality": []bond.PathQuality{{FeedbackTimeoutRatio: 0}, {FeedbackTimeoutRatio: 1}}}}
	rec := metricsSample(snap, time.Unix(1_800_000_000, 0), []bond.Alarm{{Kind: "feedback_timeout", Link: 2}})
	if err := m.Append(rec); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got metricsRecord
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Paths) != 2 || got.Paths[1].FeedbackTimeout != 1 || got.Paths[0].Budget["rate_mbps"] != 100.0 || got.Paths[0].BFDState != "up" || len(got.Alarms) != 1 {
		t.Fatalf("record wrong: %+v", got)
	}
	if _, ok := got.Paths[0].Budget["ignored"]; ok {
		t.Fatal("unlisted budget key kept")
	}
	m.maxBytes = 1
	if err := m.Append(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("no rotated backup")
	}
}
