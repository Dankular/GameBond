package main

import (
	"encoding/json"
	"io"
	"sync/atomic"
	"time"
)

var appUpload atomic.Uint64
var appDownload atomic.Uint64

type countedWriter struct {
	destination io.Writer
	counter     *atomic.Uint64
}

func (writer countedWriter) Write(packet []byte) (int, error) {
	n, err := writer.destination.Write(packet)
	writer.counter.Add(uint64(n))
	return n, err
}

func publishApplicationMetrics() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		packet, _ := json.Marshal(map[string]any{"type": "application_metrics", "uploaded_bytes": appUpload.Load(), "downloaded_bytes": appDownload.Load()})
		if writeFrame(2, packet) != nil {
			return
		}
		if publishAppUsage() != nil {
			return
		}
	}
}
