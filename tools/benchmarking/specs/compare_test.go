package specs

import (
	"testing"

	"gamebond.local/benchmarking/report"
)

func TestCompareReportsComparabilityPerBenchmark(t *testing.T) {
	makeRun := func(target, unit string) report.Run {
		return report.Run{SchemaVersion: report.SchemaVersion, Timestamp: "2026-11-13T12:00:00Z", Target: target, Mode: "specs", Results: []report.Result{
			{Key: "forwarding_rate", Name: "Forwarding rate", Method: "vendor_reported", Value: 10, Unit: unit, Note: "datasheet page 2"},
			{Key: "switching_capacity", Name: "Switching capacity", Method: "vendor_reported", Value: 20, Unit: "Gbps", Note: "datasheet page 3"},
		}}
	}
	comparison, err := Compare([]report.Run{makeRun("router-a", "Mpps"), makeRun("router-b", "Gbps")})
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Comparable {
		t.Fatal("overall comparison should be marked not comparable")
	}
	for _, benchmark := range comparison.Benchmarks {
		switch benchmark.Benchmark {
		case "forwarding_rate":
			if benchmark.Comparable {
				t.Fatal("forwarding_rate with mismatched units should not compare")
			}
		case "switching_capacity":
			if !benchmark.Comparable {
				t.Fatal("switching_capacity with matching evidence should compare")
			}
		}
	}
}
