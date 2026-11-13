package gamebond

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"gamebond.local/benchmarking/report"
)

type speedTestResult struct {
	OK        bool    `json:"ok"`
	At        int64   `json:"at"`
	DownMbps  float64 `json:"down_mbps"`
	UpMbps    float64 `json:"up_mbps"`
	LatencyMS float64 `json:"latency_ms"`
	JitterMS  float64 `json:"jitter_ms"`
	DownBytes int64   `json:"down_bytes"`
	UpBytes   int64   `json:"up_bytes"`
	Streams   int     `json:"streams"`
	Server    string  `json:"server"`
	Error     string  `json:"error"`
}

func FromSpeedTest(raw []byte, target string) (report.Run, error) {
	var input speedTestResult
	if err := json.Unmarshal(raw, &input); err != nil {
		return report.Run{}, fmt.Errorf("parse speed-test result: %w", err)
	}
	if !input.OK {
		return report.Run{}, fmt.Errorf("speed test is not successful: %s", input.Error)
	}
	if input.At <= 0 {
		return report.Run{}, fmt.Errorf("speed-test result has no valid timestamp")
	}
	if input.Streams <= 0 || input.Server == "" {
		return report.Run{}, fmt.Errorf("speed-test result is missing its stream count or server")
	}
	if input.DownBytes <= 0 || input.UpBytes <= 0 {
		return report.Run{}, fmt.Errorf("speed-test result is missing useful payload byte counts")
	}
	if target == "" {
		target = "GameBond tunnel"
	}
	results := []report.Result{
		{
			Key: "download_throughput", Name: "Download useful payload throughput", Method: "measured", Value: input.DownMbps, Unit: "Mbps",
			UsefulPayloadBytes: int64Pointer(input.DownBytes),
			Conditions:         []report.Condition{{Name: "direction", Value: "download"}, {Name: "streams", Value: strconv.Itoa(input.Streams)}, {Name: "server", Value: input.Server}, {Name: "latency_ms", Value: strconv.FormatFloat(input.LatencyMS, 'f', -1, 64)}, {Name: "jitter_ms", Value: strconv.FormatFloat(input.JitterMS, 'f', -1, 64)}},
			Note:               "Application payload bytes are reported by the existing speed test; link-layer/tunnel wire bytes are unavailable.",
		},
		{
			Key: "upload_throughput", Name: "Upload useful payload throughput", Method: "measured", Value: input.UpMbps, Unit: "Mbps",
			UsefulPayloadBytes: int64Pointer(input.UpBytes),
			Conditions:         []report.Condition{{Name: "direction", Value: "upload"}, {Name: "streams", Value: strconv.Itoa(input.Streams)}, {Name: "server", Value: input.Server}, {Name: "latency_ms", Value: strconv.FormatFloat(input.LatencyMS, 'f', -1, 64)}, {Name: "jitter_ms", Value: strconv.FormatFloat(input.JitterMS, 'f', -1, 64)}},
			Note:               "Application payload bytes are reported by the existing speed test; link-layer/tunnel wire bytes are unavailable.",
		},
	}
	run := report.Run{
		SchemaVersion: report.SchemaVersion,
		Timestamp:     time.Unix(input.At, 0).UTC().Format(time.RFC3339),
		Target:        target,
		Mode:          "gamebond",
		Results:       results,
		Warnings:      []string{"wire-byte counters and test duration are not included by the existing speed-test result; throughput is specific to the reported server and network path"},
	}
	if err := report.Validate(run); err != nil {
		return report.Run{}, err
	}
	return run, nil
}

func int64Pointer(n int64) *int64 { return &n }
