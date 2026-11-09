package scanner

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type vectors struct {
	Inventories []struct {
		Record RawRecord       `json:"record"`
		Result json.RawMessage `json:"result"`
	} `json:"inventories"`
	Adapters []Adapter `json:"adapters"`
	Scans    []struct {
		Subnet    string
		Source    string
		Index     int
		MaxHosts  int `json:"max_hosts"`
		OK        bool
		SourceOut string   `json:"source_out"`
		Targets   []string `json:"targets"`
	} `json:"scans"`
	Histories []struct {
		Limit  int
		Rounds []struct {
			Devices []Device
			T       float64
			Rows    []Device
		}
		Records map[string]Observation
		File    json.RawMessage
	} `json:"histories"`
}

func load(t *testing.T) vectors {
	f, err := os.Open("testdata/scanner-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var v vectors
	if err := json.NewDecoder(z).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func generic(t *testing.T, v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	json.Unmarshal(raw, &out)
	return out
}

func TestNormalizeMatchesPython(t *testing.T) {
	for i, in := range load(t).Inventories {
		got := Normalize(in.Record, 0)
		g := generic(t, got).(map[string]any)
		delete(g, "observed_at")
		var want any
		json.Unmarshal(in.Result, &want)
		// Python rows carry no first_seen/last_seen before History; Go omits them too.
		if !reflect.DeepEqual(g, want) {
			gj, _ := json.Marshal(g)
			wj, _ := json.Marshal(want)
			t.Fatalf("inventory %d mismatch\n got %.600s\nwant %.600s", i, gj, wj)
		}
	}
}

func TestValidateScanMatchesPython(t *testing.T) {
	v := load(t)
	accepted := 0
	for i, s := range v.Scans {
		src, targets, err := ValidateScan(s.Subnet, s.Source, s.Index, v.Adapters, s.MaxHosts)
		if (err == nil) != s.OK {
			t.Fatalf("scan %d %+v: ok=%v err=%v", i, s, err == nil, err)
		}
		if s.OK {
			accepted++
			if src != s.SourceOut || !reflect.DeepEqual(targets, s.Targets) {
				t.Fatalf("scan %d targets differ", i)
			}
		}
	}
	if accepted == 0 {
		t.Fatal("no accepted scans")
	}
}

func TestHistoryMatchesPython(t *testing.T) {
	for i, h := range load(t).Histories {
		hist, err := OpenHistory(filepath.Join(t.TempDir(), "h.json"), h.Limit)
		if err != nil {
			t.Fatal(err)
		}
		for r, round := range h.Rounds {
			rows, err := hist.Observe(round.Devices, round.T)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(generic(t, rows), generic(t, round.Rows)) && len(rows) != 0 {
				t.Fatalf("history %d round %d rows differ\n got %v\nwant %v", i, r, generic(t, rows), generic(t, round.Rows))
			}
		}
		if !reflect.DeepEqual(hist.Records(), h.Records) {
			t.Fatalf("history %d records differ", i)
		}
	}
}

func TestHistoryReadsPythonFile(t *testing.T) {
	h := load(t).Histories[0]
	path := filepath.Join(t.TempDir(), "py.json")
	os.WriteFile(path, h.File, 0o644)
	hist, err := OpenHistory(path, h.Limit)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hist.Records(), h.Records) {
		t.Fatal("Go read different records from the Python file")
	}
	for _, bad := range []string{`{"version":2,"devices":{}}`, `{"version":1,"devices":{"a":{"first_seen":1}}}`, `{"version":1,"devices":{"a":{"first_seen":-1,"last_seen":1}}}`, `nope`} {
		os.WriteFile(path, []byte(bad), 0o644)
		if _, err := OpenHistory(path, 10); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestDiscoveryJobBoundsAndCancels(t *testing.T) {
	v := load(t)
	var inflight, peak atomic.Int32
	probe := func(source, target string, timeoutMS int) (ProbeResult, error) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inflight.Add(-1)
		return ProbeResult{Address: target, Responded: target == "192.168.1.20", Status: 0}, nil
	}
	job, err := NewDiscoveryJob("192.168.1.0/24", "192.168.1.10", 3, v.Adapters, nil, 4, 400, 256, probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Targets) != 253 {
		t.Fatalf("targets = %d", len(job.Targets))
	}
	if err := job.Start(true); err != nil {
		t.Fatal(err)
	}
	if err := job.Start(true); err == nil {
		t.Fatal("second Start allowed")
	}
	job.Wait()
	s := job.Snapshot()
	if s.State != "completed" || s.Completed != 253 || peak.Load() > 4 {
		t.Fatalf("state %s completed %d peak %d", s.State, s.Completed, peak.Load())
	}
	job2, _ := NewDiscoveryJob("192.168.1.0/24", "192.168.1.10", 3, v.Adapters, nil, 2, 400, 256, probe)
	job2.Start(true)
	job2.Cancel()
	job2.Wait()
	if s := job2.Snapshot(); s.State != "cancelled" || s.Completed >= 253 {
		t.Fatalf("cancel: %s %d", s.State, s.Completed)
	}
	failing := func(string, string, int) (ProbeResult, error) { panic("boom") }
	job3, _ := NewDiscoveryJob("192.168.1.8/29", "192.168.1.10", 3, v.Adapters, nil, 2, 400, 256, failing)
	job3.Start(true)
	job3.Wait()
	if s := job3.Snapshot(); s.State != "completed" || len(s.Errors) == 0 || s.Results[0].Status != "error" {
		t.Fatalf("panicking probe: %+v", s)
	}
}
