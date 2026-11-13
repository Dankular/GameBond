package gamebond

import (
	"strings"
	"testing"
)

func TestFromSpeedTestKeepsPayloadAndMarksWireBytesUnavailable(t *testing.T) {
	raw := []byte(`{"ok":true,"at":1794571200,"down_mbps":120.5,"up_mbps":24.25,"latency_ms":18.2,"jitter_ms":1.1,"down_bytes":15000000,"up_bytes":3000000,"streams":4,"server":"speed.example"}`)
	run, err := FromSpeedTest(raw, "bonded path")
	if err != nil {
		t.Fatal(err)
	}
	if run.Target != "bonded path" || len(run.Results) != 2 {
		t.Fatalf("unexpected run metadata: %+v", run)
	}
	if run.Results[0].UsefulPayloadBytes == nil || *run.Results[0].UsefulPayloadBytes != 15000000 || run.Results[0].WireBytes != nil {
		t.Fatalf("unexpected byte accounting: %+v", run.Results[0])
	}
	if !strings.Contains(run.Warnings[0], "wire-byte counters") {
		t.Fatalf("missing wire-byte warning: %v", run.Warnings)
	}
}

func TestFromSpeedTestRejectsMissingPayloadCounters(t *testing.T) {
	raw := []byte(`{"ok":true,"at":1794571200,"down_mbps":120,"up_mbps":20,"streams":4,"server":"speed.example"}`)
	if _, err := FromSpeedTest(raw, ""); err == nil {
		t.Fatal("expected missing payload counters to be rejected")
	}
}
