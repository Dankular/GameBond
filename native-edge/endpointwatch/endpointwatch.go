// Package endpointwatch reads the alert files written by SentinelWire (github.com/chrisAS12/glowing-packets) and turns
// them into one list the dashboard can show: which process on this PC did what.
//
// Two producers are understood, and nothing else is read:
//
//   - Rustinel, the host EDR: ECS NDJSON in "<dir>/alerts.json*" (one dated file per day).
//   - PacketSentinel, the wire monitor: "<dir>/alerts.jsonl", one JSON object per line.
//
// This package only reads. It never starts, stops or configures either program, never writes to their directories and
// never sends anything anywhere. Alerts are detections, not blocks: nothing here acts on them.
//
// Privacy: user names, host names and command lines are never copied out of an alert. The process name, id and
// executable path are kept, since attributing a connection to a process is the point.
package endpointwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	maxAlerts      = 500       // alerts kept
	maxLine        = 64 << 10  // a longer line is skipped
	firstTail      = 256 << 10 // how much of an existing file is read when first attached
	maxPerPoll     = 1 << 20   // bytes read from one file per poll
	maxText        = 200       // any text copied out of an alert
	blindWindow    = 10 * time.Minute
	rustinelGlob   = "alerts.json*"
	packetSentFile = "alerts.jsonl"
)

// Config says where the two producers write.
type Config struct {
	Enabled           bool   `json:"enabled"`
	RustinelDir       string `json:"rustinel_dir"`       // directory holding alerts.json.<date>
	PacketSentinelDir string `json:"packetsentinel_dir"` // directory holding alerts.jsonl
}

// Validate checks a configuration. Directories must be absolute so that a relative path cannot resolve against
// whatever the working directory happens to be.
func (c Config) Validate() error {
	for name, dir := range map[string]string{"rustinel_dir": c.RustinelDir, "packetsentinel_dir": c.PacketSentinelDir} {
		if dir == "" {
			continue
		}
		if len(dir) > 260 || strings.ContainsRune(dir, 0) || !filepath.IsAbs(dir) {
			return fmt.Errorf("%s must be an absolute directory path", name)
		}
	}
	if c.Enabled && c.RustinelDir == "" && c.PacketSentinelDir == "" {
		return errors.New("choose at least one directory to watch")
	}
	return nil
}

// Alert is one detection in the form the GUI shows.
type Alert struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`   // rustinel or packetsentinel
	Severity string    `json:"severity"` // info, low, medium, high, critical
	Title    string    `json:"title"`
	Kind     string    `json:"kind"` // behaviour (host sensor) or wire (DNS/TLS name or address match)
	Process  string    `json:"process,omitempty"`
	PID      uint64    `json:"pid,omitempty"`
	Exe      string    `json:"exe,omitempty"`
	Remote   string    `json:"remote,omitempty"` // domain or address
	Port     int       `json:"port,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// SourceStatus says what one producer's file looks like from here.
type SourceStatus struct {
	Name    string    `json:"name"`
	Path    string    `json:"path,omitempty"`
	Found   bool      `json:"found"`
	Error   string    `json:"error,omitempty"`
	Updated time.Time `json:"updated,omitempty"`
	Alerts  int       `json:"alerts"`
}

// Snapshot is what the dashboard reads.
type Snapshot struct {
	Enabled bool           `json:"enabled"`
	Sources []SourceStatus `json:"sources"`
	Alerts  []Alert        `json:"alerts"` // newest first
	Counts  map[string]int `json:"counts"` // by severity
	// Blind is true when the EDR reported, within the last ten minutes, that its sensor lost events: detections for
	// that period did not all run. LostEvents is the total reported since this reader started.
	Blind      bool   `json:"blind"`
	BlindWhy   string `json:"blind_why,omitempty"`
	LostEvents uint64 `json:"lost_events"`
}

type tail struct {
	path    string
	offset  int64
	partial []byte
}

// Watcher follows the alert files. It is safe for concurrent use.
type Watcher struct {
	mu       sync.Mutex
	cfg      Config
	rust     tail
	wire     tail
	alerts   []Alert // oldest first
	seq      uint64
	lost     uint64
	lastLoss time.Time
	lossWhy  string
	status   map[string]*SourceStatus
	now      func() time.Time
}

// New returns a watcher for cfg. Nothing is read until Poll.
func New(cfg Config) *Watcher {
	w := &Watcher{cfg: cfg, now: time.Now}
	w.status = map[string]*SourceStatus{}
	return w
}

// SetConfig replaces the configuration. Position and history are kept only for files that stay the same.
func (w *Watcher) SetConfig(cfg Config) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cfg.RustinelDir != w.cfg.RustinelDir {
		w.rust = tail{}
	}
	if cfg.PacketSentinelDir != w.cfg.PacketSentinelDir {
		w.wire = tail{}
	}
	if !cfg.Enabled {
		w.alerts, w.lost, w.lastLoss, w.lossWhy = nil, 0, time.Time{}, ""
		w.rust, w.wire = tail{}, tail{}
	}
	w.cfg = cfg
}

// Poll reads whatever has been appended since the last call.
func (w *Watcher) Poll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = map[string]*SourceStatus{}
	if !w.cfg.Enabled {
		return
	}
	if w.cfg.RustinelDir != "" {
		st := &SourceStatus{Name: "rustinel"}
		w.status["rustinel"] = st
		path, mod, err := newestMatch(w.cfg.RustinelDir, rustinelGlob)
		switch {
		case err != nil:
			st.Error = err.Error()
		case path == "":
			st.Error = "no alerts.json file in that directory yet"
		default:
			st.Found, st.Path, st.Updated = true, path, mod
			w.readFile(&w.rust, path, "rustinel", st)
		}
	}
	if w.cfg.PacketSentinelDir != "" {
		st := &SourceStatus{Name: "packetsentinel"}
		w.status["packetsentinel"] = st
		path := filepath.Join(w.cfg.PacketSentinelDir, packetSentFile)
		info, err := os.Stat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			st.Error = "no alerts.jsonl in that directory yet"
		case err != nil:
			st.Error = err.Error()
		default:
			st.Found, st.Path, st.Updated = true, path, info.ModTime()
			w.readFile(&w.wire, path, "packetsentinel", st)
		}
	}
}

func newestMatch(dir, pattern string) (string, time.Time, error) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return "", time.Time{}, err
	}
	var best string
	var bestTime time.Time
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if best == "" || info.ModTime().After(bestTime) {
			best, bestTime = m, info.ModTime()
		}
	}
	return best, bestTime, nil
}

// readFile reads new complete lines from path. A different file than last time, or a file that got shorter, is read
// afresh; a file seen for the first time is read from near its end so a large old log is not replayed.
func (w *Watcher) readFile(t *tail, path, source string, st *SourceStatus) {
	f, err := os.Open(path)
	if err != nil {
		st.Error = err.Error()
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		st.Error = err.Error()
		return
	}
	size := info.Size()
	switch {
	case t.path != path:
		first := t.path == ""
		*t = tail{path: path}
		if first && size > firstTail {
			t.offset = size - firstTail
			t.partial = nil
			// drop the cut first line
			if _, err := f.Seek(t.offset, io.SeekStart); err == nil {
				one := make([]byte, 1)
				for {
					n, err := f.Read(one)
					if n == 1 {
						t.offset++
						if one[0] == '\n' {
							break
						}
					}
					if err != nil {
						break
					}
				}
			}
		}
	case size < t.offset:
		*t = tail{path: path}
	}
	if size == t.offset {
		st.Alerts = w.count(source)
		return
	}
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		st.Error = err.Error()
		return
	}
	n := size - t.offset
	if n > maxPerPoll {
		n = maxPerPoll
	}
	data := make([]byte, n)
	read, err := io.ReadFull(f, data)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		st.Error = err.Error()
		return
	}
	data = data[:read]
	t.offset += int64(read)
	data = append(t.partial, data...)
	t.partial = nil
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			if len(data) <= maxLine {
				t.partial = append([]byte(nil), data...)
			}
			break
		}
		line := bytes.TrimSpace(data[:i])
		data = data[i+1:]
		if len(line) == 0 || len(line) > maxLine {
			continue
		}
		w.ingest(source, line)
	}
	st.Alerts = w.count(source)
}

func (w *Watcher) count(source string) int {
	n := 0
	for _, a := range w.alerts {
		if a.Source == source {
			n++
		}
	}
	return n
}

func (w *Watcher) ingest(source string, line []byte) {
	var a *Alert
	switch source {
	case "rustinel":
		a = w.parseRustinel(line)
	case "packetsentinel":
		a = parsePacketSentinel(line)
	}
	if a == nil {
		return
	}
	w.seq++
	a.ID = fmt.Sprintf("%s-%d", source, w.seq)
	w.alerts = append(w.alerts, *a)
	if len(w.alerts) > maxAlerts {
		w.alerts = append([]Alert(nil), w.alerts[len(w.alerts)-maxAlerts:]...)
	}
}

// clean makes text from a file safe to show: no control characters, bounded length.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxText {
		s = s[:maxText]
		for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 { // do not end inside a multi-byte character
			s = s[:len(s)-1]
		}
	}
	return s
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "informational", "info":
		return "info"
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	}
	return "medium"
}

// lossChannels are the sensor-loss channels the EDR documents as leaving it blind (docs/output.md, "Sensor loss
// alerts"). The enrichment channels are not listed: those events were still evaluated.
var lossChannels = map[string]bool{"sensor_events": true, "etw_session": true, "ebpf_ring": true, "ebpf_oversized": true, "ebpf_map_full": true, "macos_esf": true, "macos_bpf": true}

func (w *Watcher) parseRustinel(line []byte) *Alert {
	var m map[string]json.RawMessage
	if json.Unmarshal(line, &m) != nil {
		return nil
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(m[k], &s)
		return s
	}
	num := func(k string) uint64 {
		var n uint64
		_ = json.Unmarshal(m[k], &n)
		return n
	}
	when := parseTime(str("@timestamp"))
	if when.IsZero() {
		when = w.now().UTC()
	}
	// Operational alerts about the agent itself are health, not detections.
	if str("edr.rule.engine") == "Agent" || str("event.dataset") == "edr.agent" {
		if channel := str("edr.agent.loss.channel"); channel != "" && lossChannels[channel] {
			dropped := num("edr.agent.loss.dropped")
			w.lost += dropped
			if dropped > 0 {
				w.lastLoss, w.lossWhy = when, clean(channel)
			}
		}
		return nil
	}
	title := clean(str("rule.name"))
	if title == "" {
		return nil
	}
	a := &Alert{Time: when, Source: "rustinel", Severity: severity(str("edr.rule.severity")), Title: title, Kind: "behaviour",
		Process: clean(str("process.name")), PID: num("process.pid"), Exe: clean(str("process.executable"))}
	switch {
	case str("destination.domain") != "":
		a.Remote = clean(str("destination.domain"))
	case str("dns.question.name") != "":
		a.Remote = clean(str("dns.question.name"))
	case str("destination.ip") != "":
		a.Remote = clean(str("destination.ip"))
	}
	a.Port = int(num("destination.port"))
	a.Detail = clean(strings.TrimPrefix(str("edr.rule.engine")+" "+str("event.dataset"), " "))
	return a
}

func parsePacketSentinel(line []byte) *Alert {
	var r struct {
		Timestamp string `json:"timestamp_utc"`
		Indicator string `json:"indicator"`
		Rule      string `json:"matched_rule"`
		Feed      string `json:"source_feed"`
		MatchType string `json:"match_type"`
		Protocol  string `json:"protocol"`
		DstIP     string `json:"dst_ip"`
		DstPort   int    `json:"dst_port"`
		Process   string `json:"process_name"`
		PID       uint64 `json:"process_pid"`
		Exe       string `json:"process_exe"`
		Layer     string `json:"detection_layer"`
	}
	if json.Unmarshal(line, &r) != nil || r.Indicator == "" {
		return nil
	}
	when := parseTime(r.Timestamp)
	if when.IsZero() {
		when = time.Now().UTC()
	}
	title := "Connection to a listed indicator"
	if r.Rule != "" {
		title = clean(r.Rule)
	}
	a := &Alert{Time: when, Source: "packetsentinel", Severity: "medium", Title: title, Kind: "wire", Process: clean(r.Process), PID: r.PID, Exe: clean(r.Exe),
		Remote: clean(r.Indicator), Port: r.DstPort}
	if r.DstPort < 0 || r.DstPort > 65535 {
		a.Port = 0
	}
	a.Detail = clean(strings.Join(nonEmpty(r.Feed, r.MatchType, strings.ToUpper(r.Protocol), r.Layer), " · "))
	if a.Remote == "" {
		a.Remote = clean(r.DstIP)
	}
	return a
}

func nonEmpty(items ...string) []string {
	var out []string
	for _, s := range items {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// Snapshot returns the current view, newest alert first.
func (w *Watcher) Snapshot() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := Snapshot{Enabled: w.cfg.Enabled, Counts: map[string]int{}, LostEvents: w.lost, Sources: []SourceStatus{}}
	for _, name := range []string{"rustinel", "packetsentinel"} {
		if st, ok := w.status[name]; ok {
			s.Sources = append(s.Sources, *st)
		}
	}
	s.Alerts = make([]Alert, 0, len(w.alerts))
	for i := len(w.alerts) - 1; i >= 0; i-- {
		s.Alerts = append(s.Alerts, w.alerts[i])
		s.Counts[w.alerts[i].Severity]++
	}
	sort.SliceStable(s.Alerts, func(i, j int) bool { return s.Alerts[i].Time.After(s.Alerts[j].Time) })
	if !w.lastLoss.IsZero() && w.now().Sub(w.lastLoss) < blindWindow {
		s.Blind, s.BlindWhy = true, w.lossWhy
	}
	return s
}
