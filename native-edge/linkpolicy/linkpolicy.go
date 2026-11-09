// Package linkpolicy ports gamebond/link_policy.py: validated per-link roles,
// data caps with billing-cycle accounting, and the persistent usage ledger.
// The ledger file format is identical to Python's (version 1), so either
// implementation can read the other's .runtime/link-usage.json.
package linkpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gamebond.local/nativeedge/status"
)

var ErrInvalid = errors.New("linkpolicy: invalid value")

var Roles = []string{"primary", "secondary", "backup", "never"}

type Policy struct {
	Role          string  `json:"role"`
	UploadMbps    float64 `json:"upload_mbps"`
	DownloadMbps  float64 `json:"download_mbps"`
	DailyBytes    int64   `json:"daily_bytes"`
	MonthlyBytes  int64   `json:"monthly_bytes"`
	ResetDay      int     `json:"reset_day"`
	Overlimit     string  `json:"overlimit"`
	OverlimitMbps float64 `json:"overlimit_mbps"`
}

// Default fills the Python dataclass defaults for unset fields.
func Default() Policy {
	return Policy{Role: "primary", ResetDay: 1, Overlimit: "stop", OverlimitMbps: .2}
}

func (p Policy) Validate() error {
	ok := false
	for _, r := range Roles {
		ok = ok || p.Role == r
	}
	if !ok {
		return fmt.Errorf("%w: link role", ErrInvalid)
	}
	for _, v := range []float64{p.UploadMbps, p.DownloadMbps, p.OverlimitMbps} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 10000 {
			return fmt.Errorf("%w: link rates must be finite values from 0 to 10000 Mbps", ErrInvalid)
		}
	}
	for _, v := range []int64{p.DailyBytes, p.MonthlyBytes} {
		if v < 0 || v > 1e16 {
			return fmt.Errorf("%w: data cap", ErrInvalid)
		}
	}
	if p.ResetDay < 1 || p.ResetDay > 31 {
		return fmt.Errorf("%w: billing reset day", ErrInvalid)
	}
	if p.Overlimit != "stop" && p.Overlimit != "throttle" {
		return fmt.Errorf("%w: overlimit behaviour", ErrInvalid)
	}
	if p.Overlimit == "throttle" && p.OverlimitMbps == 0 {
		return fmt.Errorf("%w: overlimit throttle must be positive", ErrInvalid)
	}
	return nil
}

type Usage struct {
	DailyBytes, MonthlyBytes int64
	CycleStart               string
}

type Effective struct {
	Role                     string
	Blocked, CapReached      bool
	UploadMbps, DownloadMbps float64
}

func (p Policy) Effective(u Usage) Effective {
	reached := (p.DailyBytes != 0 && u.DailyBytes >= p.DailyBytes) || (p.MonthlyBytes != 0 && u.MonthlyBytes >= p.MonthlyBytes)
	e := Effective{Role: p.Role, Blocked: p.Role == "never" || (reached && p.Overlimit == "stop"), CapReached: reached,
		UploadMbps: p.UploadMbps, DownloadMbps: p.DownloadMbps}
	if reached && p.Overlimit == "throttle" {
		throttle := func(r float64) float64 {
			if r != 0 {
				return math.Min(r, p.OverlimitMbps)
			}
			return p.OverlimitMbps
		}
		e.UploadMbps, e.DownloadMbps = throttle(e.UploadMbps), throttle(e.DownloadMbps)
	}
	return e
}

func daysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// CycleStart is the most recent billing reset date on or before day, clamping
// reset days beyond the month's length to its last day.
func CycleStart(day time.Time, resetDay int) time.Time {
	y, m, d := day.Date()
	current := time.Date(y, m, min(resetDay, daysIn(y, m)), 0, 0, 0, 0, time.UTC)
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	if !today.Before(current) {
		return current
	}
	prev := time.Date(y, m, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	py, pm, _ := prev.Date()
	return time.Date(py, pm, min(resetDay, daysIn(py, pm)), 0, 0, 0, 0, time.UTC)
}

type counts struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

type Ledger struct {
	path  string
	Clock func() time.Time
	links map[string]map[string]*counts
	dirty bool
}

// OpenLedger loads path if it exists, applying Python's size and shape limits.
func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{path: path, Clock: time.Now, links: map[string]map[string]*counts{}}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() > 4<<20 {
		return nil, fmt.Errorf("%w: usage ledger exceeds its size limit", ErrInvalid)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec struct {
		Version int                           `json:"version"`
		Links   map[string]map[string]*counts `json:"links"`
	}
	if err = json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if rec.Version != 1 || rec.Links == nil || len(rec.Links) > 64 {
		return nil, fmt.Errorf("%w: unsupported usage ledger", ErrInvalid)
	}
	for _, buckets := range rec.Links {
		if len(buckets) > 400 {
			return nil, fmt.Errorf("%w: usage history", ErrInvalid)
		}
		for day, c := range buckets {
			if _, err = time.Parse("2006-01-02", day); err != nil || c == nil || c.Upload < 0 || c.Download < 0 {
				return nil, fmt.Errorf("%w: usage counters", ErrInvalid)
			}
		}
	}
	l.links = rec.Links
	return l, nil
}

func (l *Ledger) today() string { return l.Clock().Format("2006-01-02") }

func (l *Ledger) Add(key string, upload, download int64) error {
	if upload < 0 || download < 0 {
		return fmt.Errorf("%w: usage increments must be nonnegative", ErrInvalid)
	}
	buckets := l.links[key]
	if buckets == nil {
		if len(l.links) >= 64 {
			return fmt.Errorf("%w: too many metered links", ErrInvalid)
		}
		buckets = map[string]*counts{}
		l.links[key] = buckets
	}
	c := buckets[l.today()]
	if c == nil {
		c = &counts{}
		buckets[l.today()] = c
	}
	c.Upload += upload
	c.Download += download
	if len(buckets) > 400 {
		days := make([]string, 0, len(buckets))
		for d := range buckets {
			days = append(days, d)
		}
		sort.Strings(days)
		for _, d := range days[:len(days)-400] {
			delete(buckets, d)
		}
	}
	l.dirty = true
	return nil
}

func (l *Ledger) Usage(key string, p Policy) Usage {
	now := l.Clock()
	y, m, d := now.Date()
	end := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	start := CycleStart(end, p.ResetDay).Format("2006-01-02")
	endKey := end.Format("2006-01-02")
	var u Usage
	u.CycleStart = start
	for day, c := range l.links[key] {
		if day >= start && day <= endKey {
			u.MonthlyBytes += c.Upload + c.Download
		}
		if day == endKey {
			u.DailyBytes = c.Upload + c.Download
		}
	}
	return u
}

// Save writes the ledger atomically; it is a no-op when nothing changed.
func (l *Ledger) Save() error {
	if !l.dirty {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	if err := status.WriteJSON(l.path, map[string]any{"version": 1, "links": l.links}); err != nil {
		return err
	}
	l.dirty = false
	return nil
}

// UnmarshalJSON starts from the Python dataclass defaults so omitted fields
// (role, reset_day, overlimit, ...) behave exactly as they do there.
func (p *Policy) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if fields == nil {
		return fmt.Errorf("%w: link policy must be an object", ErrInvalid)
	}
	for key := range fields {
		switch key {
		case "role", "upload_mbps", "download_mbps", "daily_bytes", "monthly_bytes", "reset_day", "overlimit", "overlimit_mbps":
		default:
			return fmt.Errorf("%w: unknown link policy field %s", ErrInvalid, key)
		}
	}
	type plain Policy
	d := plain(Default())
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	*p = Policy(d)
	return nil
}
