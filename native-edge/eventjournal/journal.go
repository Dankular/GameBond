// Package eventjournal preserves the desktop's first-use and connection history
// in the version-1 format used by gamebond/glass_logs.py.
package eventjournal

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/appevents"
	"gamebond.local/nativeedge/atomicio"
)

const maxBytes = 4 << 20

type Event struct {
	ID          int64          `json:"id"`
	Source      string         `json:"source"`
	Kind        string         `json:"kind"`
	Text        string         `json:"text"`
	Timestamp   float64        `json:"timestamp"`
	Application map[string]any `json:"application"`
	Destination any            `json:"destination"`
}

func (e *Event) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, key := range []string{"id", "source", "kind", "text", "timestamp"} {
		value, ok := fields[key]
		if !ok || (key != "kind" && string(value) == "null") {
			return errors.New("invalid stored event: missing " + key)
		}
	}
	type plain Event
	var value plain
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*e = Event(value)
	return nil
}

type Snapshot struct {
	Version     int     `json:"version"`
	Sequence    int64   `json:"sequence"`
	ReadThrough int64   `json:"read_through"`
	Events      []Event `json:"events"`
	Error       string  `json:"error,omitempty"`
}

type Journal struct {
	mu       sync.Mutex
	path     string
	limit    int
	doc      Snapshot
	sources  map[string]bool
	previous string
	closed   bool
	pending  chan []byte // one latest snapshot, never a queue of every tick
	done     chan struct{}
	now      func() time.Time
	write    func([]byte) error
}

// Open keeps a corrupt existing file intact and reports the error in Snapshot.
func Open(path string, limit int) (*Journal, error) {
	if limit < 1 || limit > 2048 {
		return nil, errors.New("event journal limit must be 1..2048")
	}
	j := &Journal{path: path, limit: limit, sources: map[string]bool{}, doc: Snapshot{Version: 1, Events: []Event{}}, pending: make(chan []byte, 1), done: make(chan struct{}), now: time.Now}
	if path != "" {
		var saved Snapshot
		err := atomicio.ReadJSONShared(path, maxBytes, &saved)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			j.doc.Error = err.Error()
		}
		if err == nil {
			if saved.Version != 1 || saved.Events == nil || saved.Sequence < 0 || saved.ReadThrough < 0 {
				j.doc.Error = "invalid event journal"
			} else {
				valid := true
				for _, e := range saved.Events {
					valid = valid && e.ID > 0 && e.ID <= saved.Sequence && e.Source != "" && !math.IsNaN(e.Timestamp) && !math.IsInf(e.Timestamp, 0)
				}
				if !valid {
					j.doc.Error = "invalid stored event"
				} else {
					saved.Error = ""
					j.doc = saved
				}
			}
		}
	}
	j.trimLocked()
	j.write = func(raw []byte) error {
		if err := os.MkdirAll(filepath.Dir(j.path), 0700); err != nil {
			return err
		}
		return atomicio.WriteFileAtomic(j.path, raw, 0600)
	}
	go j.writeLoop()
	return j, nil
}

func (j *Journal) trimLocked() {
	if len(j.doc.Events) > j.limit {
		j.doc.Events = append([]Event{}, j.doc.Events[len(j.doc.Events)-j.limit:]...)
	}
	j.sources = map[string]bool{}
	for _, e := range j.doc.Events {
		j.sources[e.Source] = true
	}
}

func (j *Journal) writeLoop() {
	defer close(j.done)
	for raw := range j.pending {
		if err := j.write(raw); err != nil {
			j.writeError(err)
		}
	}
}

func (j *Journal) writeError(err error) { j.mu.Lock(); j.doc.Error = err.Error(); j.mu.Unlock() }

func (j *Journal) saveLocked() {
	if j.path == "" || j.closed || j.doc.Error != "" {
		return
	}
	var raw []byte
	for {
		var err error
		raw, err = json.Marshal(j.doc)
		if err != nil {
			j.doc.Error = err.Error()
			return
		}
		if len(raw) <= maxBytes {
			break
		}
		if len(j.doc.Events) == 0 {
			j.doc.Error = "event journal exceeds 4 MiB"
			return
		}
		j.doc.Events = j.doc.Events[1:]
	}
	j.trimLocked()
	select {
	case j.pending <- raw:
	default:
		select {
		case <-j.pending:
		default:
		}
		j.pending <- raw
	}
}

func (j *Journal) appendLocked(e Event) bool {
	if j.closed || j.sources[e.Source] {
		return false
	}
	j.doc.Sequence++
	e.ID = j.doc.Sequence
	if e.Timestamp == 0 {
		e.Timestamp = float64(j.now().UnixNano()) / 1e9
	}
	j.doc.Events = append(j.doc.Events, e)
	j.trimLocked()
	return true
}

// Python formats float timestamps with a trailing .0 for integral values.
func sourceStamp(v any) string {
	if f, ok := v.(float64); ok {
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	return fmt.Sprint(v)
}

func timestamp(v any) (float64, bool) {
	var f float64
	switch v := v.(type) {
	case float64:
		f = v
	case int:
		f = float64(v)
	case int64:
		f = float64(v)
	case json.Number:
		var err error
		f, err = v.Float64()
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return f, !math.IsNaN(f) && !math.IsInf(f, 0)
}

func (j *Journal) ingestLocked(events []any) bool {
	changed := false
	for _, value := range events {
		e, ok := value.(map[string]any)
		if !ok {
			continue
		}
		a, _ := e["application"].(map[string]any)
		stamp, ok := timestamp(e["timestamp"])
		if !ok || e["id"] == nil {
			continue
		}
		path, _ := a["path"].(string)
		name, _ := a["name"].(string)
		if name == "" {
			name = "Application"
		}
		source := "app:" + fmt.Sprint(e["id"]) + ":" + sourceStamp(e["timestamp"]) + ":" + appevents.Casefold(path)
		// Python JSON may have stored an integral timestamp as int or float.
		// A JSON-decoded Go status uses float64 for both: retain deduplication
		// against either spelling when importing an existing Python journal.
		if j.sources[source] {
			continue
		}
		if stamp == math.Trunc(stamp) {
			prefix := "app:" + fmt.Sprint(e["id"]) + ":" + strconv.FormatFloat(stamp, 'f', -1, 64)
			if j.sources[prefix+":"+appevents.Casefold(path)] || j.sources[prefix+".0:"+appevents.Casefold(path)] {
				continue
			}
		}
		// Copy application metadata so callers cannot mutate the stored document.
		var application map[string]any
		if raw, err := json.Marshal(a); err == nil {
			_ = json.Unmarshal(raw, &application)
		}
		changed = j.appendLocked(Event{Source: source, Kind: "new_app_tunnel_use", Text: name + " used the tunnel for the first time", Timestamp: stamp, Application: application, Destination: e["destination"]}) || changed
	}
	return changed
}

// Observe is driven by background status sampling, including when the window
// is hidden. Repeated status snapshots cannot duplicate first-use events.
func (j *Journal) Observe(runtime map[string]any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	changed := false
	if events, ok := runtime["app_events"].(map[string]any); ok {
		if rows, ok := events["events"].([]any); ok {
			changed = j.ingestLocked(rows)
		}
	}
	state := ""
	text := "Tunnel disconnected"
	if len(runtime) > 0 {
		paths := []any{}
		enabled, healthy := 0, 0
		transport, _ := runtime["transport"].(map[string]any)
		if rows, ok := transport["paths"].([]any); ok {
			for _, value := range rows {
				p, ok := value.(map[string]any)
				if !ok {
					continue
				}
				on := p["enabled"] != false
				good := p["healthy"] == true
				paths = append(paths, []any{p["interface_index"], good, on})
				if on {
					enabled++
					if good {
						healthy++
					}
				}
			}
		}
		raw, _ := json.Marshal([]any{runtime["pid"], runtime["state"], paths})
		state = string(raw)
		peer := "Unavailable"
		if p, ok := runtime["peer"].([]any); ok && len(p) > 0 {
			peer = fmt.Sprint(p[0])
		}
		text = fmt.Sprintf("Tunnel %v · %d/%d enabled links · VPS %s", runtime["state"], healthy, enabled, peer)
	}
	if j.previous != "" && state != j.previous {
		changed = j.appendLocked(Event{Source: fmt.Sprintf("state:%d:%d", j.now().UnixNano(), j.doc.Sequence+1), Kind: "connection_state", Text: text}) || changed
	}
	j.previous = state
	if changed {
		j.saveLocked()
	}
}

// Ingest restores first-use events from the daemon's existing app-history file.
func (j *Journal) Ingest(events []any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.ingestLocked(events) {
		j.saveLocked()
	}
}

func (j *Journal) MarkRead() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.doc.ReadThrough = j.doc.Sequence
	j.saveLocked()
}

func (j *Journal) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	// Marshal a bounded snapshot to avoid sharing nested application maps.
	raw, _ := json.Marshal(j.doc)
	var out Snapshot
	_ = json.Unmarshal(raw, &out)
	return out
}

func (j *Journal) Close() {
	j.mu.Lock()
	if !j.closed {
		j.closed = true
		close(j.pending)
	}
	j.mu.Unlock()
	<-j.done
}
