// Package alerting turns the daemon's status document into notices for the person at the PC. It is
// edge-triggered: a condition must hold for a while before it is raised, it is raised once, and a
// recovery notice follows when it clears. The same conditions exist as Prometheus rules under
// ops/prometheus for fleet monitoring; this is the local view that needs no server.
package alerting

import (
	"fmt"
	"sort"
	"time"
)

// Severity orders notices.
type Severity string

const (
	Critical Severity = "critical"
	Warning  Severity = "warning"
	Info     Severity = "info"
)

// Notice is one thing to tell the person.
type Notice struct {
	Key      string
	Severity Severity
	Title    string
	Body     string
	Resolved bool
}

type state struct {
	since  time.Time // when the condition first held
	raised bool
}

// Watcher keeps the state between observations. It is not safe for concurrent use.
type Watcher struct {
	conds    map[string]*state
	switches float64
	seen     bool
}

// NewWatcher returns an empty watcher.
func NewWatcher() *Watcher { return &Watcher{conds: map[string]*state{}} }

type cond struct {
	key      string
	holding  bool
	hold     time.Duration
	severity Severity
	title    string
	body     string
	recover  string
}

// Observe evaluates doc (the decoded status document) at now and returns notices to show.
func (w *Watcher) Observe(now time.Time, doc map[string]any) []Notice {
	var out []Notice
	var cs []cond

	ready, total := 0, 0
	if t, ok := doc["transport"].(map[string]any); ok {
		if ps, ok := t["paths"].([]any); ok {
			for _, p := range ps {
				if m, ok := p.(map[string]any); ok {
					total++
					if r, _ := m["ready"].(bool); r {
						ready++
					}
				}
			}
		}
	}
	running := doc["state"] == "running" || doc["state"] == nil
	if total > 0 && running {
		cs = append(cs,
			cond{"no_links", ready == 0, 5 * time.Second, Critical, "GameBond: no connection", "Every uplink is down. Traffic is not flowing.", "Connection restored"},
			cond{"redundancy", ready > 0 && ready < total, 30 * time.Second, Warning, "GameBond: reduced redundancy",
				fmt.Sprintf("Only %d of %d uplinks are working; a second failure will cut the connection.", ready, total), "All uplinks are back"})
	}
	if ex, ok := doc["exit"].(map[string]any); ok {
		active, _ := ex["active"].(string)
		onBackup, _ := ex["on_backup"].(bool)
		searching, _ := ex["searching"].(bool)
		cs = append(cs,
			cond{"exit_backup", onBackup, 0, Warning, "GameBond: on the backup exit", fmt.Sprintf("Traffic now leaves through %s. The public IP address changed and open connections were reset.", active), "Back on the primary exit"},
			cond{"exit_search", searching, 3 * time.Second, Critical, "GameBond: exit server not answering", "Trying the standby exit server.", "Exit server answering again"})
		if n, ok := ex["switches"].(float64); ok {
			if w.seen && n > w.switches && !onBackup {
				out = append(out, Notice{Key: "exit_switch", Severity: Warning, Title: "GameBond: exit server changed", Body: "Now using " + active})
			}
			w.switches = n
		}
	}
	if al, ok := doc["alarms"].([]any); ok {
		kinds := map[string]string{}
		for _, a := range al {
			if m, ok := a.(map[string]any); ok {
				k, _ := m["kind"].(string)
				d, _ := m["detail"].(string)
				kinds[k] = d
			}
		}
		keys := make([]string, 0, len(kinds))
		for k := range kinds {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			cs = append(cs, cond{"alarm:" + k, true, 30 * time.Second, Warning, "GameBond: " + k, kinds[k], "Cleared: " + k})
		}
	}
	if burn, ok := burnRates(doc); ok {
		cs = append(cs, cond{"slo_burn", burn[0] > 14.4 && burn[1] > 6, 0, Critical, "GameBond: delivery objective at risk",
			fmt.Sprintf("Packet loss is spending the error budget %.0fx faster than sustainable.", burn[0]), "Delivery objective back on track"})
	}
	w.seen = true
	present := map[string]bool{}
	for _, c := range cs {
		present[c.key] = true
	}
	// A condition that is no longer evaluated at all (an alarm that left the list, the transport
	// going away) counts as cleared.
	for key, st := range w.conds {
		if !present[key] && st.raised {
			out = append(out, Notice{Key: key, Severity: Info, Title: "GameBond", Body: "Cleared: " + key, Resolved: true})
		}
		if !present[key] {
			delete(w.conds, key)
		}
	}
	for _, c := range cs {
		st := w.conds[c.key]
		if st == nil {
			st = &state{}
			w.conds[c.key] = st
		}
		switch {
		case c.holding:
			if st.since.IsZero() {
				st.since = now
			}
			if !st.raised && now.Sub(st.since) >= c.hold {
				st.raised = true
				out = append(out, Notice{Key: c.key, Severity: c.severity, Title: c.title, Body: c.body})
			}
		default:
			if st.raised {
				out = append(out, Notice{Key: c.key, Severity: Info, Title: "GameBond", Body: c.recover, Resolved: true})
			}
			st.since, st.raised = time.Time{}, false
		}
	}
	return out
}

// burnRates returns the delivery burn rate over 1 h and 6 h.
func burnRates(doc map[string]any) ([2]float64, bool) {
	s, ok := doc["slo"].(map[string]any)
	if !ok {
		return [2]float64{}, false
	}
	ev, ok := s["evaluation"].(map[string]any)
	if !ok {
		return [2]float64{}, false
	}
	ws, ok := ev["windows"].([]any)
	if !ok {
		return [2]float64{}, false
	}
	var out [2]float64
	found := 0
	for _, w := range ws {
		m, _ := w.(map[string]any)
		hours, _ := m["window_hours"].(float64)
		burn, _ := m["delivery_burn_rate"].(float64)
		switch hours {
		case 1:
			out[0], found = burn, found+1
		case 6:
			out[1], found = burn, found+1
		}
	}
	return out, found == 2
}
