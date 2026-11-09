package dashboard

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"gamebond.local/nativeedge/appevents"
	"gamebond.local/nativeedge/apppolicy"
)

type AppRate struct {
	ObservedAt float64  `json:"observed_at"`
	Down       *float64 `json:"down_Bps"`
	Up         *float64 `json:"up_Bps"`
}

type AppActivity struct {
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	PIDs         []int64   `json:"pids"`
	Downloaded   uint64    `json:"downloaded_bytes"`
	Uploaded     uint64    `json:"uploaded_bytes"`
	Connections  int       `json:"active_connections"`
	Destinations []string  `json:"destinations"`
	Down         *float64  `json:"down_Bps"`
	Up           *float64  `json:"up_Bps"`
	History      []AppRate `json:"history"`
}

type AppActivitySnapshot struct {
	Available    bool          `json:"available"`
	ObservedAt   float64       `json:"observed_at"`
	Applications []AppActivity `json:"applications"`
}

type appProcess struct {
	Path         string   `json:"path"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	PID          int64    `json:"pid"`
	Created      string   `json:"created_filetime"`
	Generation   any      `json:"generation"`
	Downloaded   uint64   `json:"downloaded_bytes"`
	Uploaded     uint64   `json:"uploaded_bytes"`
	Connections  int      `json:"active_connections"`
	Destinations []string `json:"destinations"`
}

type appBaseline struct {
	At                   float64
	Downloaded, Uploaded uint64
}

// AppActivitySampler uses status timestamps and process generations. Repeated
// reads, resets, PID reuse and tunnel restarts cannot invent a traffic spike.
// Sample is called by the background sampler even when Protect is hidden.
type AppActivitySampler struct {
	previous  map[string]appBaseline
	histories map[string][]AppRate
	session   string
	stamp     float64
	last      AppActivitySnapshot
}

func (s *AppActivitySampler) Sample(doc map[string]any, now time.Time) AppActivitySnapshot {
	stamp, _ := doc["updated_at"].(float64)
	if doc["state"] != "running" || stamp <= 0 || math.IsNaN(stamp) || math.IsInf(stamp, 0) || float64(now.UnixNano())/1e9-stamp > 5 {
		*s = AppActivitySampler{}
		return AppActivitySnapshot{Applications: []AppActivity{}}
	}
	session := fmt.Sprint(doc["pid"]) + ":" + fmt.Sprint(doc["created"])
	if session != s.session || stamp < s.stamp {
		*s = AppActivitySampler{session: session}
	}
	if stamp == s.stamp {
		return s.last
	}
	var rows []json.RawMessage
	_ = typedValue(doc["applications"], &rows)
	merged := map[string]*AppActivity{}
	unmeasured := map[string]bool{}
	next := map[string]appBaseline{}
	if s.histories == nil {
		s.histories = map[string][]AppRate{}
	}
	for _, raw := range rows[:min(len(rows), 512)] {
		var p appProcess
		if json.Unmarshal(raw, &p) != nil {
			continue
		}
		// Missing/null counters are not a measured zero.
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		if len(fields["downloaded_bytes"]) == 0 || string(fields["downloaded_bytes"]) == "null" || len(fields["uploaded_bytes"]) == 0 || string(fields["uploaded_bytes"]) == "null" {
			continue
		}
		key, err := apppolicy.CanonicalPath(p.Path)
		if err != nil {
			continue
		}
		identity := fmt.Sprintf("%s:%d:%s:%v", key, p.PID, p.Created, p.Generation)
		if _, dup := next[identity]; dup {
			continue
		}
		old, has := s.previous[identity]
		next[identity] = appBaseline{stamp, p.Downloaded, p.Uploaded}
		row := merged[key]
		if row == nil {
			name := p.Name
			if name == "" {
				parts := strings.Split(key, `\`)
				name = parts[len(parts)-1]
			}
			row = &AppActivity{Path: key, Name: name, Version: p.Version, PIDs: []int64{}, Destinations: []string{}}
			merged[key] = row
		}
		if has && stamp > old.At && p.Downloaded >= old.Downloaded && p.Uploaded >= old.Uploaded {
			down, up := float64(p.Downloaded-old.Downloaded)/(stamp-old.At), float64(p.Uploaded-old.Uploaded)/(stamp-old.At)
			if row.Down == nil {
				row.Down = new(float64)
				row.Up = new(float64)
			}
			*row.Down += down
			*row.Up += up
		} else {
			unmeasured[key] = true
		}
		row.Downloaded += p.Downloaded
		row.Uploaded += p.Uploaded
		row.Connections += max(0, p.Connections)
		row.PIDs = append(row.PIDs, p.PID)
		for _, host := range p.Destinations[:min(len(p.Destinations), 8)] {
			found := false
			for _, h := range row.Destinations {
				found = found || h == host
			}
			if !found && len(row.Destinations) < 16 {
				row.Destinations = append(row.Destinations, host)
			}
		}
	}
	result := AppActivitySnapshot{Available: true, ObservedAt: stamp, Applications: []AppActivity{}}
	histories := map[string][]AppRate{}
	for key, row := range merged {
		if unmeasured[key] {
			row.Down, row.Up = nil, nil
		}
		history := append([]AppRate{}, s.histories[key]...)
		history = append(history, AppRate{stamp, row.Down, row.Up})
		if len(history) > 60 {
			history = history[len(history)-60:]
		}
		row.History = history
		histories[key] = history
		result.Applications = append(result.Applications, *row)
	}
	sort.Slice(result.Applications, func(i, j int) bool {
		a, b := result.Applications[i], result.Applications[j]
		if (a.Connections > 0) != (b.Connections > 0) {
			return a.Connections > 0
		}
		x, y := appevents.Casefold(a.Name), appevents.Casefold(b.Name)
		if x != y {
			return x < y
		}
		return a.Path < b.Path
	})
	s.previous, s.histories, s.stamp, s.last = next, histories, stamp, result
	return result
}
