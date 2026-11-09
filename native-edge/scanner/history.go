package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Observation is the first/last time GameBond saw a device (not device uptime).
type Observation struct {
	FirstSeen float64 `json:"first_seen"`
	LastSeen  float64 `json:"last_seen"`
}

// History persists first/last observations in a version-1 JSON file shared
// with the Python implementation.
type History struct {
	mu      sync.Mutex
	path    string
	limit   int
	records map[string]*Observation
	order   []string // insertion order, as in a Python dict (breaks last_seen ties)
}

// OpenHistory loads path (if present). An empty path keeps history in memory.
func OpenHistory(path string, limit int) (*History, error) {
	if limit < 1 || limit > 4096 {
		return nil, errors.New("Invalid device history limit")
	}
	h := &History{path: path, limit: limit, records: map[string]*Observation{}}
	if path == "" {
		return h, nil
	}
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	if st.Size() > 4*1024*1024 {
		return nil, errors.New("Device history is too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Version float64                       `json:"version"`
		Devices map[string]map[string]float64 `json:"devices"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Version != 1 || doc.Devices == nil {
		return nil, errors.New("Invalid device history")
	}
	if len(doc.Devices) > limit {
		return nil, errors.New("Device history exceeds its limit")
	}
	h.order = fileKeyOrder(raw)
	for k, v := range doc.Devices {
		f, okF := v["first_seen"]
		l, okL := v["last_seen"]
		if len(v) != 2 || !okF || !okL || f < 0 || l < 0 || math.IsInf(f, 0) || math.IsInf(l, 0) || math.IsNaN(f) || math.IsNaN(l) {
			return nil, errors.New("Invalid device observation timestamp")
		}
		h.records[k] = &Observation{f, l}
	}
	if len(h.order) != len(h.records) {
		h.order = h.order[:0]
		for k := range h.records {
			h.order = append(h.order, k)
		}
		sort.Strings(h.order)
	}
	return h, nil
}

// fileKeyOrder returns the "devices" keys in file order.
func fileKeyOrder(raw []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil
		}
		if kt != "devices" {
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return nil
			}
			continue
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('{') {
			return nil
		}
		var keys []string
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil
			}
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return nil
			}
			keys = append(keys, k.(string))
		}
		return keys
	}
	return nil
}

// Observe records the devices and returns copies carrying first_seen/last_seen.
func (h *History) Observe(devices []Device, observedAt float64) ([]Device, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rows := make([]Device, 0, len(devices))
	for _, d := range devices {
		who := d.MAC
		if who == "" {
			who = d.Address
		}
		key := strconv.Itoa(d.InterfaceIndex) + ":" + strings.ToLower(who)
		rec, ok := h.records[key]
		if !ok {
			rec = &Observation{observedAt, observedAt}
			h.records[key] = rec
			h.order = append(h.order, key)
		}
		rec.FirstSeen = math.Min(rec.FirstSeen, observedAt)
		rec.LastSeen = math.Max(rec.LastSeen, observedAt)
		d.FirstSeen, d.LastSeen = rec.FirstSeen, rec.LastSeen
		rows = append(rows, d)
	}
	if len(h.records) > h.limit {
		keys := append([]string(nil), h.order...)
		sort.SliceStable(keys, func(i, j int) bool { return h.records[keys[i]].LastSeen < h.records[keys[j]].LastSeen })
		drop := map[string]bool{}
		for _, k := range keys[:len(keys)-h.limit] {
			delete(h.records, k)
			drop[k] = true
		}
		kept := h.order[:0]
		for _, k := range h.order {
			if !drop[k] {
				kept = append(kept, k)
			}
		}
		h.order = kept
	}
	if h.path != "" {
		if err := os.MkdirAll(filepath.Dir(h.path), 0o755); err != nil {
			return rows, err
		}
		var buf bytes.Buffer
		buf.WriteString(`{"version": 1, "devices": {`)
		for i, k := range h.order {
			kb, _ := json.Marshal(k)
			vb, _ := json.Marshal(h.records[k])
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.Write(kb)
			buf.WriteString(": ")
			buf.Write(vb)
		}
		buf.WriteString("}}")
		raw := buf.Bytes()
		tmp := fmt.Sprintf("%s.%d.tmp", h.path, time.Now().UnixNano())
		if err := os.WriteFile(tmp, raw, 0o644); err != nil {
			return rows, err
		}
		if err := os.Rename(tmp, h.path); err != nil {
			os.Remove(tmp)
			return rows, err
		}
	}
	return rows, nil
}

// Records returns a copy of the stored observations.
func (h *History) Records() map[string]Observation {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]Observation, len(h.records))
	for k, v := range h.records {
		out[k] = *v
	}
	return out
}
