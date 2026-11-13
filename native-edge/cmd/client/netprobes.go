package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"gamebond.local/nativeedge/atomicio"
)

// netProbes keeps what the netstack helper reports about the internet side of the tunnel: round trips to a few
// well-known hosts, and speed tests. The widget asks for a test by writing speedtest-request.json next to the
// status file; the daemon passes it to the helper, which runs the test through the tunnel (so it uses every link)
// and reports progress and a result. The last successful result is kept on disk so it survives a restart.
type netProbes struct {
	mu       sync.Mutex
	dir      string
	respond  func(any) error // sends control JSON to the helper
	pings    map[string]any  // the last internet_ping event
	running  bool
	id       string
	phase    string
	current  float64
	elapsed  float64
	started  time.Time
	last     map[string]any // last successful result
	lastFail map[string]any // last failed attempt, until a test succeeds
	now      func() time.Time
}

const (
	speedRequestFile = "speedtest-request.json"
	speedLastFile    = "speedtest-last.json"
	// A helper that never answers must not leave the widget showing "running" forever. The helper gives up after 90 s.
	speedStaleAfter = 100 * time.Second
	requestMaxAge   = 30 * time.Second
)

var speedIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func newNetProbes(dir string, respond func(any) error) *netProbes {
	n := &netProbes{dir: dir, respond: respond, now: time.Now}
	var last map[string]any
	if raw, err := os.ReadFile(filepath.Join(dir, speedLastFile)); err == nil && json.Unmarshal(raw, &last) == nil && last["ok"] == true {
		n.last = last
	}
	return n
}

// num reads a JSON number whichever way it was decoded (the bridge uses json.Number).
func num(v any) float64 {
	switch x := v.(type) {
	case json.Number:
		f, _ := x.Float64()
		return f
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	}
	return 0
}

func str(v any) string { s, _ := v.(string); return s }

// onEvent consumes the helper's probe events; it reports whether it handled the record.
func (n *netProbes) onEvent(m map[string]any) bool {
	switch m["type"] {
	case "internet_ping":
		results, _ := m["results"].([]any)
		out := make([]any, 0, len(results))
		for _, r := range results {
			if rm, ok := r.(map[string]any); ok {
				entry := map[string]any{"name": str(rm["name"]), "ok": rm["ok"] == true}
				if rm["ok"] == true {
					entry["ms"] = num(rm["ms"])
				} else {
					entry["error"] = str(rm["error"])
				}
				out = append(out, entry)
			}
		}
		n.mu.Lock()
		n.pings = map[string]any{"at": num(m["at"]), "results": out}
		n.mu.Unlock()
		return true
	case "speedtest_progress":
		n.mu.Lock()
		if n.running && str(m["id"]) == n.id {
			n.phase, n.current, n.elapsed = str(m["phase"]), num(m["mbps"]), num(m["elapsed_s"])
		}
		n.mu.Unlock()
		return true
	case "speedtest_result":
		n.mu.Lock()
		defer n.mu.Unlock()
		if str(m["id"]) != n.id && n.running {
			return true // an answer to a request this widget did not make
		}
		n.running, n.phase, n.current = false, "", 0
		at := int64(num(m["at"]))
		if m["ok"] == true {
			n.last = map[string]any{"ok": true, "at": at, "down_mbps": num(m["down_mbps"]), "up_mbps": num(m["up_mbps"]), "latency_ms": num(m["latency_ms"]),
				"jitter_ms": num(m["jitter_ms"]), "down_bytes": num(m["down_bytes"]), "up_bytes": num(m["up_bytes"]), "streams": num(m["streams"]), "server": str(m["server"])}
			n.lastFail = nil
			if raw, err := json.Marshal(n.last); err == nil {
				_ = atomicio.WriteFileAtomic(filepath.Join(n.dir, speedLastFile), raw, 0o600)
			}
		} else {
			n.lastFail = map[string]any{"at": at, "error": str(m["error"])}
		}
		return true
	}
	return false
}

// poll runs once a second: it picks up a request from the widget and clears a test the helper never finished.
func (n *netProbes) poll() {
	n.mu.Lock()
	if n.running && n.now().Sub(n.started) > speedStaleAfter {
		n.running, n.phase, n.current = false, "", 0
		n.lastFail = map[string]any{"at": n.now().Unix(), "error": "the speed test did not finish"}
	}
	n.mu.Unlock()
	path := filepath.Join(n.dir, speedRequestFile)
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	raw, rerr := os.ReadFile(path)
	_ = os.Remove(path)
	if rerr != nil || n.now().Sub(st.ModTime()) > requestMaxAge {
		return // a request left over from before a restart is not acted on
	}
	var req struct {
		Action string `json:"action"`
		ID     string `json:"id"`
	}
	if json.Unmarshal(raw, &req) != nil {
		return
	}
	switch req.Action {
	case "start":
		if !speedIDPattern.MatchString(req.ID) {
			return
		}
		n.mu.Lock()
		if n.running || n.respond == nil {
			n.mu.Unlock()
			return
		}
		n.running, n.id, n.phase, n.current, n.elapsed, n.started, n.lastFail = true, req.ID, "starting", 0, 0, n.now(), nil
		respond := n.respond
		n.mu.Unlock()
		if err := respond(map[string]any{"type": "speedtest_request", "id": req.ID}); err != nil {
			n.mu.Lock()
			n.running = false
			n.lastFail = map[string]any{"at": n.now().Unix(), "error": "could not reach the network helper"}
			n.mu.Unlock()
		}
	case "cancel":
		if n.respond != nil {
			_ = n.respond(map[string]any{"type": "speedtest_cancel"})
		}
	}
}

func (n *netProbes) pingStatus() any {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.pings == nil {
		return nil
	}
	out := map[string]any{"at": n.pings["at"], "results": n.pings["results"]}
	return out
}

func (n *netProbes) speedStatus() map[string]any {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]any{"running": n.running, "last": n.last}
	if n.running {
		out["id"], out["phase"], out["current_mbps"], out["elapsed_s"] = n.id, n.phase, n.current, n.elapsed
	}
	if n.lastFail != nil {
		out["error"] = n.lastFail
	}
	return out
}
