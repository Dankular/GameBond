// Package tray holds the notification-area agent: the state model that decides
// the icon colour, tooltip and menu text (gamebond/tray.py TrayAgent.update),
// the single-instance lease, and the Windows shell integration.
package tray

import (
	"fmt"
	"strings"
)

// Icon colours, as in Python's idle / connected / busy images.
const (
	Idle      = "#000000"
	Connected = "#00c853"
	Busy      = "#f2be70"
)

// Model mirrors TrayAgent's state: (state, busy, healthy, total, issue) plus the
// flash toggle, and the derived icon, tooltip and Connect/Disconnect item.
type Model struct {
	state       snapshot
	flashOn     bool
	Color       string
	Title       string
	ToggleLabel string
	// ToggleEnabled is false while the tunnel is changing state.
	ToggleEnabled bool
}

type snapshot struct {
	state   string
	busy    bool
	healthy int
	total   int
	issue   bool
}

func NewModel() *Model {
	m := &Model{state: snapshot{state: "idle"}, Color: Idle, Title: "GameBond · Disconnected"}
	m.refreshToggle()
	return m
}

func (m *Model) refreshToggle() {
	m.ToggleLabel = "Connect"
	if m.state.state == "running" {
		m.ToggleLabel = "Disconnect"
	}
	m.ToggleEnabled = !m.state.busy
}

// truthy is Python's bool() for the JSON values a status file can hold.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// Update applies one status sample (rt nil = no runtime). It reports whether the
// icon must be redrawn, like the early return in the Python method.
func (m *Model) Update(rt map[string]any, busy bool, problem string) bool {
	var paths []any
	if rt != nil {
		if t, ok := rt["transport"].(map[string]any); ok {
			if list, ok := t["paths"].([]any); ok {
				for _, p := range list {
					pm, _ := p.(map[string]any)
					if enabled, has := pm["enabled"]; !has || truthy(enabled) {
						paths = append(paths, pm)
					}
				}
			}
		} else if _, has := rt["transport"]; has {
			paths = nil
		}
	}
	healthy := 0
	for _, p := range paths {
		if truthy(p.(map[string]any)["healthy"]) {
			healthy++
		}
	}
	state := "idle"
	if rt != nil {
		if s, ok := rt["state"].(string); ok {
			state = s
		}
	}
	issue := problem != "" || state == "failed" || (state == "running" && (len(paths) == 0 || healthy < len(paths)))
	snap := snapshot{state, busy || state == "starting" || state == "connecting" || state == "stopping", healthy, len(paths), issue}
	if snap == m.state && !issue {
		return false
	}
	m.state = snap
	color := Idle
	if issue {
		m.flashOn = !m.flashOn
		if m.flashOn {
			color = Busy
		}
	} else {
		m.flashOn = false
		if state == "running" && healthy > 0 {
			color = Connected
		} else if snap.busy {
			color = Busy
		}
	}
	m.Color = color
	switch {
	case issue:
		m.Title = fmt.Sprintf("GameBond · Network problem · %d/%d links", healthy, len(paths))
	case state == "running":
		m.Title = fmt.Sprintf("GameBond · %d/%d links · %s", healthy, len(paths), peerHost(rt))
	case busy:
		m.Title = "GameBond · Connecting…"
	default:
		m.Title = "GameBond · " + capitalize(state)
	}
	m.refreshToggle()
	return true
}

func peerHost(rt map[string]any) string {
	if p, ok := rt["peer"].([]any); ok && len(p) > 0 {
		return fmt.Sprint(p[0])
	}
	return ""
}

// capitalize is Python's str.capitalize for the ASCII state names.
func capitalize(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
