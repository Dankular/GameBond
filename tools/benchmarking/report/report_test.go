package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validRun() Run {
	return Run{SchemaVersion: SchemaVersion, Timestamp: "2026-11-13T12:00:00Z", Target: "router-a", Mode: "device", Results: []Result{{Key: "forwarding_rate", Name: "Forwarding rate", Method: "measured", Value: 10, Unit: "Mpps"}}}
}

func TestValidateRejectsUnknownDeviceKeyAndEmptyCondition(t *testing.T) {
	run := validRun()
	run.Results[0].Key = "forwarding_rates"
	if err := Validate(run); err == nil || !strings.Contains(err.Error(), "unsupported device benchmark") {
		t.Fatalf("Validate() error = %v, want unsupported key", err)
	}
	run = validRun()
	run.Results[0].Conditions = []Condition{{Name: "packet_size", Value: " "}}
	if err := Validate(run); err == nil || !strings.Contains(err.Error(), "name and value are required") {
		t.Fatalf("Validate() error = %v, want empty condition rejection", err)
	}
}

func TestReadRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":  `{"schema_version":1,"unknown":true}`,
		"trailing": `{"schema_version":1} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path); err == nil {
				t.Fatal("Read() unexpectedly accepted malformed report")
			}
		})
	}
}

func TestWriteJSONDoesNotOverwriteWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteJSON(path, validRun(), false); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, validRun(), false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second WriteJSON() error = %v, want existing-file error", err)
	}
	if err := WriteJSON(path, validRun(), true); err != nil {
		t.Fatalf("forced replacement failed: %v", err)
	}
}
