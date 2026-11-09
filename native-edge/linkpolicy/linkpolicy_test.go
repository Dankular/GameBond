package linkpolicy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type vectors struct {
	Cycles []struct {
		Day      string
		ResetDay int `json:"reset_day"`
		Start    string
	}
	Effective []struct {
		Policy map[string]any
		Usage  struct {
			DailyBytes   int64 `json:"daily_bytes"`
			MonthlyBytes int64 `json:"monthly_bytes"`
		}
		Result struct {
			Role                     string
			Blocked                  bool
			CapReached               bool    `json:"cap_reached"`
			UploadMbps, DownloadMbps float64 `json:"-"`
			Up                       float64 `json:"upload_mbps"`
			Down                     float64 `json:"download_mbps"`
		}
	}
	Rejected []map[string]any
	Ops      []struct {
		Day      string
		Key      string
		Upload   int64
		Download int64
	}
	Checks []struct {
		After    int
		Day, Key string
		ResetDay int `json:"reset_day"`
		Usage    struct {
			DailyBytes   int64  `json:"daily_bytes"`
			MonthlyBytes int64  `json:"monthly_bytes"`
			CycleStart   string `json:"cycle_start"`
		}
	}
	LedgerFile string `json:"ledger_file"`
}

func load(t *testing.T) vectors {
	raw, err := os.ReadFile("testdata/linkpolicy-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err = json.NewDecoder(zr).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func fromMap(m map[string]any) Policy {
	p := Default()
	for k, v := range m {
		switch k {
		case "role":
			p.Role = v.(string)
		case "overlimit":
			p.Overlimit = v.(string)
		case "upload_mbps", "download_mbps", "overlimit_mbps":
			f := math.Inf(1) // the generator writes non-finite values as null
			if v != nil {
				f = v.(float64)
			}
			switch k {
			case "upload_mbps":
				p.UploadMbps = f
			case "download_mbps":
				p.DownloadMbps = f
			default:
				p.OverlimitMbps = f
			}
		case "daily_bytes":
			p.DailyBytes = int64(v.(float64))
		case "monthly_bytes":
			p.MonthlyBytes = int64(v.(float64))
		case "reset_day":
			p.ResetDay = int(v.(float64))
		}
	}
	return p
}

func day(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestPolicyAndCyclesMatchPython(t *testing.T) {
	v := load(t)
	for _, c := range v.Cycles {
		if got := CycleStart(day(c.Day), c.ResetDay).Format("2006-01-02"); got != c.Start {
			t.Fatalf("cycle %s reset %d: go %s python %s", c.Day, c.ResetDay, got, c.Start)
		}
	}
	for i, e := range v.Effective {
		p := fromMap(e.Policy)
		if err := p.Validate(); err != nil {
			t.Fatalf("case %d rejected: %v", i, err)
		}
		got := p.Effective(Usage{DailyBytes: e.Usage.DailyBytes, MonthlyBytes: e.Usage.MonthlyBytes})
		w := e.Result
		if got.Role != w.Role || got.Blocked != w.Blocked || got.CapReached != w.CapReached || got.UploadMbps != w.Up || got.DownloadMbps != w.Down {
			t.Fatalf("case %d: go %+v python %+v", i, got, w)
		}
	}
	for i, r := range v.Rejected {
		if fromMap(r).Validate() == nil {
			t.Fatalf("rejected case %d accepted: %v", i, r)
		}
	}
}

func TestLedgerReplayMatchesPythonAndReadsItsFile(t *testing.T) {
	v := load(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "link-usage.json")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	var clock time.Time
	l.Clock = func() time.Time { return clock }
	checks := v.Checks
	next := 0
	for step, op := range v.Ops {
		clock = day(op.Day).Add(12 * time.Hour)
		if err = l.Add(op.Key, op.Upload, op.Download); err != nil {
			t.Fatal(err)
		}
		for next < len(checks) && checks[next].After == step {
			c := checks[next]
			clock = day(c.Day).Add(12 * time.Hour)
			p := Default()
			p.ResetDay = c.ResetDay
			got := l.Usage(c.Key, p)
			if got.DailyBytes != c.Usage.DailyBytes || got.MonthlyBytes != c.Usage.MonthlyBytes || got.CycleStart != c.Usage.CycleStart {
				t.Fatalf("step %d key %s reset %d: go %+v python %+v", step, c.Key, c.ResetDay, got, c.Usage)
			}
			next++
		}
	}
	if next != len(checks) {
		t.Fatalf("only %d of %d usage checks ran", next, len(checks))
	}
	if err = l.Save(); err != nil {
		t.Fatal(err)
	}
	// Python's file loads in Go and agrees with the replayed state.
	pyPath := filepath.Join(dir, "from-python.json")
	os.WriteFile(pyPath, []byte(v.LedgerFile), 0o600)
	pl, err := OpenLedger(pyPath)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(path)
	var goDoc, pyDoc map[string]any
	json.Unmarshal(a, &goDoc)
	json.Unmarshal([]byte(v.LedgerFile), &pyDoc)
	if !jsonEqual(goDoc, pyDoc) {
		t.Fatal("saved ledger differs from the file Python wrote")
	}
	_ = pl
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func TestLedgerRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"ver": `{"version":2,"links":{}}`, "neg": `{"version":1,"links":{"0":{"2024-01-01":{"upload":-1,"download":0}}}}`,
		"day": `{"version":1,"links":{"0":{"nope":{"upload":1,"download":0}}}}`} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := OpenLedger(p); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestMeterCountsGrowthOnlyAndBlocksAtTheCap(t *testing.T) {
	l, _ := OpenLedger(filepath.Join(t.TempDir(), "usage.json"))
	l.Clock = func() time.Time { return time.Date(2024, 3, 10, 9, 0, 0, 0, time.UTC) }
	capped := Default()
	capped.DailyBytes = 3000
	capped.UploadMbps = 20
	m := NewMeter(l, []string{"25", "16"}, []Policy{capped, Default()})
	out, changed, err := m.Update([][2]uint64{{0, 0}, {0, 0}})
	if err != nil || !changed || out[0].Blocked || out[0].UploadMbps != 20 {
		t.Fatalf("initial %+v changed %v err %v", out, changed, err)
	}
	if _, changed, _ = m.Update([][2]uint64{{1000, 500}, {0, 0}}); changed {
		t.Fatal("unchanged policy reported as changed")
	}
	// Counters are cumulative: repeating them adds nothing.
	m.Update([][2]uint64{{1000, 500}, {0, 0}})
	if u := l.Usage("25", capped); u.DailyBytes != 1500 {
		t.Fatalf("double counting: %d", u.DailyBytes)
	}
	out, changed, _ = m.Update([][2]uint64{{2500, 1500}, {10, 10}})
	if !changed || !out[0].Blocked || out[1].Blocked {
		t.Fatalf("cap not enforced: %+v changed %v", out, changed)
	}
	if out[0].Role != 0 {
		t.Fatalf("role %d", out[0].Role)
	}
}
