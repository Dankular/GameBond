package device

import (
	"strings"
	"testing"

	"gamebond.local/benchmarking/report"
)

func TestAssessMarksMissingLabPrerequisitesSkipped(t *testing.T) {
	assessment, err := Assess(Setup{Target: "lab-router", AvailablePrerequisites: []string{"traffic generator at every tested port", "isolated test topology"}})
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(map[string]string, len(assessment.Results))
	for _, result := range assessment.Results {
		statuses[result.Key] = result.Status
	}
	if statuses["switching_capacity"] != "ready" {
		t.Fatalf("switching capacity status = %q, want ready", statuses["switching_capacity"])
	}
	if statuses["forwarding_rate"] != "skipped" {
		t.Fatalf("forwarding rate status = %q, want skipped", statuses["forwarding_rate"])
	}
}

func TestValidateRunRequiresCatalogUnitAndConditions(t *testing.T) {
	run := report.Run{SchemaVersion: report.SchemaVersion, Timestamp: "2026-11-13T12:00:00Z", Target: "lab-router", Mode: "device", Prerequisites: []string{"packet-capable traffic generator", "isolated test topology"}, Results: []report.Result{{Key: "forwarding_rate", Name: "Forwarding rate", Method: "measured", Value: 10, Unit: "Gbps"}}}
	if err := ValidateRun(run); err == nil || !strings.Contains(err.Error(), `requires "Mpps"`) {
		t.Fatalf("ValidateRun() error = %v, want catalog unit rejection", err)
	}
	run.Results[0].Unit = "Mpps"
	if err := ValidateRun(run); err == nil || !strings.Contains(err.Error(), "missing condition") {
		t.Fatalf("ValidateRun() error = %v, want missing conditions rejection", err)
	}
}
