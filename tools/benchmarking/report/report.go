package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const SchemaVersion = 1

type Condition struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Result struct {
	Key                string      `json:"key"`
	Name               string      `json:"name"`
	Method             string      `json:"method"` // measured or vendor_reported
	Value              float64     `json:"value"`
	Unit               string      `json:"unit"`
	Conditions         []Condition `json:"conditions,omitempty"`
	UsefulPayloadBytes *int64      `json:"useful_payload_bytes,omitempty"`
	WireBytes          *int64      `json:"wire_bytes,omitempty"`
	Note               string      `json:"note,omitempty"`
}

type Run struct {
	SchemaVersion int      `json:"schema_version"`
	Timestamp     string   `json:"timestamp"`
	Target        string   `json:"target"`
	Mode          string   `json:"mode"`
	Results       []Result `json:"results"`
	Warnings      []string `json:"warnings,omitempty"`
	Prerequisites []string `json:"prerequisites,omitempty"`
}

var DeviceKeys = []string{
	"switching_capacity",
	"total_non_blocking_throughput",
	"forwarding_rate",
	"supported_vlans",
	"mac_address_table_size",
	"ipv4_static_routes",
	"packet_buffer_size",
	"multi_wan_load_balancing",
	"dpi_traffic_identification",
}

func Validate(run Run) error {
	if run.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version: want %d", SchemaVersion)
	}
	if strings.TrimSpace(run.Timestamp) == "" {
		return errors.New("timestamp: required")
	}
	if _, err := time.Parse(time.RFC3339, run.Timestamp); err != nil {
		return fmt.Errorf("timestamp: expected RFC3339: %w", err)
	}
	if strings.TrimSpace(run.Target) == "" {
		return errors.New("target: required")
	}
	if run.Mode != "device" && run.Mode != "specs" && run.Mode != "gamebond" {
		return fmt.Errorf("mode: unsupported value %q", run.Mode)
	}
	if len(run.Results) == 0 {
		return errors.New("results: at least one result is required")
	}
	for i, result := range run.Results {
		prefix := fmt.Sprintf("results[%d]", i)
		if strings.TrimSpace(result.Key) == "" {
			return fmt.Errorf("%s.key: required", prefix)
		}
		if run.Mode != "gamebond" && !contains(DeviceKeys, result.Key) {
			return fmt.Errorf("%s.key: unsupported device benchmark %q", prefix, result.Key)
		}
		if strings.TrimSpace(result.Name) == "" {
			return fmt.Errorf("%s.name: required", prefix)
		}
		if result.Method != "measured" && result.Method != "vendor_reported" {
			return fmt.Errorf("%s.method: must be measured or vendor_reported", prefix)
		}
		if result.Method == "vendor_reported" && strings.TrimSpace(result.Note) == "" {
			return fmt.Errorf("%s.note: vendor-reported values must identify their source", prefix)
		}
		if math.IsNaN(result.Value) || math.IsInf(result.Value, 0) || result.Value < 0 {
			return fmt.Errorf("%s.value: must be a finite non-negative number", prefix)
		}
		if strings.TrimSpace(result.Unit) == "" {
			return fmt.Errorf("%s.unit: required", prefix)
		}
		for j, condition := range result.Conditions {
			if strings.TrimSpace(condition.Name) == "" || strings.TrimSpace(condition.Value) == "" {
				return fmt.Errorf("%s.conditions[%d]: name and value are required", prefix, j)
			}
		}
		if result.UsefulPayloadBytes != nil && *result.UsefulPayloadBytes < 0 {
			return fmt.Errorf("%s.useful_payload_bytes: must be non-negative", prefix)
		}
		if result.WireBytes != nil && *result.WireBytes < 0 {
			return fmt.Errorf("%s.wire_bytes: must be non-negative", prefix)
		}
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func Read(path string) (Run, error) {
	var run Run
	raw, err := os.ReadFile(path)
	if err != nil {
		return run, fmt.Errorf("read %s: %w", path, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&run); err != nil {
		return run, fmt.Errorf("parse %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return run, fmt.Errorf("parse %s: trailing JSON value", path)
		}
		return run, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := Validate(run); err != nil {
		return run, fmt.Errorf("validate %s: %w", path, err)
	}
	return run, nil
}

func WriteJSON(path string, run Run, force bool) error {
	if err := Validate(run); err != nil {
		return err
	}
	return Write(path, run, force)
}

func Write(path string, value any, force bool) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".benchmark-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write report: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	if force {
		if err := replaceFile(tmpName, path); err != nil {
			return fmt.Errorf("write report %s: %w", path, err)
		}
	} else {
		// A hard link creates the destination atomically and fails if it already exists.
		if err := os.Link(tmpName, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("output %s already exists (use --force to replace it)", path)
			}
			return fmt.Errorf("write report %s: %w", path, err)
		}
	}
	return nil
}
