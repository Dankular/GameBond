package main

import (
	"bytes"
	"encoding/json"
	"sync/atomic"
	"testing"
)

func TestPerIdentityApplicationCountersAndFramesStayBounded(t *testing.T) {
	appUsages.Lock()
	appUsages.rows = make(map[string]*appUsage)
	appUsages.Unlock()
	identity := &appIdentity{42, "134000000000000000"}
	usage, release := trackAppConnection(identity, "1.1.1.1:443")
	var global atomic.Uint64
	destination := new(bytes.Buffer)
	writer := countAppWriter(destination, &global, usage, true)
	if _, err := writer.Write([]byte("real-app-payload")); err != nil {
		t.Fatal(err)
	}
	recordAppDatagram(usage, 32, false)
	release()
	if global.Load() != 16 || usage.upload.Load() != 16 || usage.download.Load() != 32 || usage.active.Load() != 0 {
		t.Fatal("per-app counters diverged from successful I/O")
	}
	original := emitAppMetricsFrame
	defer func() { emitAppMetricsFrame = original }()
	frames := 0
	emitAppMetricsFrame = func(endpoint byte, packet []byte) error {
		if endpoint != 2 || len(packet) > 1280 {
			t.Fatal("metadata frame exceeds IPC budget")
		}
		var record map[string]any
		if json.Unmarshal(packet, &record) != nil || record["type"] != "app_metrics" {
			t.Fatal("invalid app metrics")
		}
		frames++
		return nil
	}
	if err := publishAppUsage(); err != nil {
		t.Fatal(err)
	}
	if frames != 1 {
		t.Fatal("successful identity I/O was not published")
	}
	if err := publishAppUsage(); err != nil {
		t.Fatal(err)
	}
	if frames != 1 {
		t.Fatal("unchanged idle rows should not generate repeated metadata")
	}
}
