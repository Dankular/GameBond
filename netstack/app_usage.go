package main

import (
	"encoding/json"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const trackedAppProcessLimit = 512

type appUsage struct {
	identity     appIdentity
	generation   uint64
	upload       atomic.Uint64
	download     atomic.Uint64
	active       atomic.Int64
	touched      atomic.Int64
	dirty        atomic.Bool
	destinations []string
}

var appUsages = struct {
	sync.Mutex
	rows       map[string]*appUsage
	generation uint64
	skipped    uint64
}{rows: make(map[string]*appUsage)}

var emitAppMetricsFrame = writeFrame

func trackAppConnection(identity *appIdentity, destination string) (*appUsage, func()) {
	if identity == nil {
		return nil, func() {}
	}
	key := identity.CreatedFiletime + "|" + strconv.FormatUint(uint64(identity.PID), 10)
	appUsages.Lock()
	row := appUsages.rows[key]
	if row == nil {
		if len(appUsages.rows) >= trackedAppProcessLimit {
			var oldest string
			var when int64
			for key, candidate := range appUsages.rows {
				if candidate.active.Load() == 0 && (oldest == "" || candidate.touched.Load() < when) {
					oldest = key
					when = candidate.touched.Load()
				}
			}
			if oldest == "" {
				appUsages.skipped++
				appUsages.Unlock()
				return nil, func() {}
			}
			delete(appUsages.rows, oldest)
		}
		appUsages.generation++
		row = &appUsage{identity: *identity, generation: appUsages.generation}
		appUsages.rows[key] = row
	}
	found := false
	for _, host := range row.destinations {
		if host == destination {
			found = true
			break
		}
	}
	if !found {
		row.destinations = append(row.destinations, destination)
		if len(row.destinations) > 8 {
			row.destinations = row.destinations[len(row.destinations)-8:]
		}
	}
	row.active.Add(1)
	row.touched.Store(time.Now().UnixMilli())
	row.dirty.Store(true)
	appUsages.Unlock()
	return row, func() { row.active.Add(-1); row.touched.Store(time.Now().UnixMilli()); row.dirty.Store(true) }
}

func rememberAppDestination(row *appUsage, destination string) {
	if row == nil {
		return
	}
	appUsages.Lock()
	defer appUsages.Unlock()
	for _, host := range row.destinations {
		if host == destination {
			return
		}
	}
	row.destinations = append(row.destinations, destination)
	if len(row.destinations) > 8 {
		row.destinations = row.destinations[len(row.destinations)-8:]
	}
	row.dirty.Store(true)
}

type appCountedWriter struct {
	writer countedWriter
	usage  *appUsage
	upload bool
}

func (writer appCountedWriter) Write(packet []byte) (int, error) {
	n, err := writer.writer.Write(packet)
	if n > 0 {
		if writer.upload {
			writer.usage.upload.Add(uint64(n))
		} else {
			writer.usage.download.Add(uint64(n))
		}
		writer.usage.touched.Store(time.Now().UnixMilli())
		writer.usage.dirty.Store(true)
	}
	return n, err
}

func countAppWriter(destination io.Writer, counter *atomic.Uint64, usage *appUsage, upload bool) io.Writer {
	writer := countedWriter{destination, counter}
	if usage == nil {
		return writer
	}
	return appCountedWriter{writer, usage, upload}
}

func recordAppDatagram(usage *appUsage, n int, upload bool) {
	if usage == nil || n <= 0 {
		return
	}
	if upload {
		usage.upload.Add(uint64(n))
	} else {
		usage.download.Add(uint64(n))
	}
	usage.touched.Store(time.Now().UnixMilli())
	usage.dirty.Store(true)
}

func publishAppUsage() error {
	appUsages.Lock()
	rows := make([]map[string]any, 0, len(appUsages.rows))
	for _, row := range appUsages.rows {
		if !row.dirty.Swap(false) {
			continue
		}
		rows = append(rows, map[string]any{"pid": row.identity.PID, "created_filetime": row.identity.CreatedFiletime, "generation": row.generation,
			"uploaded_bytes": row.upload.Load(), "downloaded_bytes": row.download.Load(), "active_connections": row.active.Load(),
			"destinations": append([]string(nil), row.destinations...), "last_activity": float64(row.touched.Load()) / 1000})
	}
	skipped := appUsages.skipped
	appUsages.Unlock()
	for len(rows) > 0 {
		count := 1
		var packet []byte
		for count <= len(rows) {
			next, err := json.Marshal(map[string]any{"type": "app_metrics", "applications": rows[:count], "tracked_process_limit": trackedAppProcessLimit, "skipped_identities": skipped})
			if err != nil {
				return err
			}
			if len(next) > 1200 {
				count--
				break
			}
			packet = next
			count++
		}
		if count > len(rows) {
			count = len(rows)
		}
		if count == 0 {
			rows = rows[1:]
			continue
		}
		if err := emitAppMetricsFrame(2, packet); err != nil {
			return err
		}
		rows = rows[count:]
	}
	return nil
}
