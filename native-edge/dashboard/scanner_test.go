package dashboard

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gamebond.local/nativeedge/scanner"
)

func scannerFixture(t *testing.T) (*Server, string, *atomic.Int32) {
	s, url, config, _ := start(t)
	s.o.RootPath = filepath.Dir(config)
	var probes atomic.Int32
	s.o.ScanInventory = func() (scanner.Inventory, error) {
		return scanner.Inventory{ObservedAt: scanner.Now(), Adapters: []scanner.Adapter{{Index: 22, Name: "Test LAN", Address: "192.168.1.2", Subnet: "192.168.1.0/24", DiscoverySubnet: "192.168.1.0/24", Up: true}}, Devices: []scanner.Device{{InterfaceIndex: 22, Address: "192.168.1.1", MAC: "02:00:00:00:00:01", State: "Stale", Source: "neighbor_cache"}}}, nil
	}
	s.o.ScanProbe = func(source, target string, timeout int) (scanner.ProbeResult, error) {
		probes.Add(1)
		if source != "192.168.1.2" || timeout != 300 {
			t.Errorf("unbounded/unbound probe %s %d", source, timeout)
		}
		rtt := 3
		return scanner.ProbeResult{Address: target, Responded: true, RTTMS: &rtt}, nil
	}
	return s, url[:strings.Index(url, "/?t=")] + "/api/scanner", &probes
}

func scanSnapshot(t *testing.T, s *Server, url string) scanner.Snapshot {
	t.Helper()
	code, body := do(t, "GET", url+"?job=1", s.token, "")
	var doc struct {
		Job scanner.Snapshot `json:"job"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &doc) != nil {
		t.Fatal(code, body)
	}
	return doc.Job
}

func awaitScan(t *testing.T, s *Server, url string) scanner.Snapshot {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		v := scanSnapshot(t, s, url)
		if v.State != "running" {
			return v
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("scan did not finish")
	return scanner.Snapshot{}
}

func TestScannerPassiveAndBoundedDiscoveryHistory(t *testing.T) {
	s, url, probes := scannerFixture(t)
	for _, path := range []string{url, url + "?job=1", url + "?refresh=1"} {
		if code, body := do(t, "GET", path, s.token, ""); code != 200 {
			t.Fatal(code, body)
		}
	}
	if probes.Load() != 0 {
		t.Fatal("passive reads probed the LAN")
	}
	request := `{"action":"start","subnet":"192.168.1.0/30","source":"192.168.1.2","interface_index":22}`
	if code, body := do(t, "POST", url, s.token, request); code != 202 {
		t.Fatal(code, body)
	}
	job := awaitScan(t, s, url)
	if job.State != "completed" || job.Total != 1 || job.Completed != 1 || probes.Load() != 1 || !job.Results[0].Responded {
		t.Fatal(job, probes.Load())
	}
	// Wait for the terminal observation writer, then reopen the actual file.
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		h, err := scanner.OpenHistory(filepath.Join(s.o.RootPath, ".runtime", "scanner-history.json"), 4096)
		if err == nil {
			if rec, ok := h.Records()["22:02:00:00:00:00:01"]; ok && rec.LastSeen > rec.FirstSeen {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("ICMP observation did not persist with the neighbor MAC history key")
}

func TestScannerRejectsOffLANAndRevalidatesAtStart(t *testing.T) {
	s, url, probes := scannerFixture(t)
	for _, body := range []string{
		`{"action":"start","subnet":"8.8.8.0/24","source":"192.168.1.2","interface_index":22}`,
		`{"action":"start","subnet":"192.168.2.0/24","source":"192.168.1.2","interface_index":22}`,
		`{"action":"start","subnet":"192.168.1.0/24","source":"192.168.1.5","interface_index":22}`,
		`{"action":"start","subnet":"192.168.0.0/16","source":"192.168.1.2","interface_index":22}`,
		`{"action":"start","probe":"custom"}`, `null`,
	} {
		if code, b := do(t, "POST", url, s.token, body); code != 422 {
			t.Fatal(code, b)
		}
	}
	var calls atomic.Int32
	read := s.o.ScanInventory
	s.o.ScanInventory = func() (scanner.Inventory, error) {
		inv, err := read()
		if calls.Add(1) > 1 {
			inv.Adapters[0].Up = false
		}
		return inv, err
	}
	if code, body := do(t, "POST", url, s.token, `{"action":"start","subnet":"192.168.1.0/30","source":"192.168.1.2","interface_index":22}`); code != 422 {
		t.Fatal(code, body)
	}
	if probes.Load() != 0 {
		t.Fatal("rejected scan sent traffic")
	}
}

func TestScannerCancelDuplicateAndAuthentication(t *testing.T) {
	s, url, _ := scannerFixture(t)
	for _, method := range []string{"GET", "POST"} {
		if code, _ := do(t, method, url, "", `{"action":"start"}`); code != 403 {
			t.Fatal(code)
		}
	}
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	s.o.ScanProbe = func(source, target string, timeout int) (scanner.ProbeResult, error) {
		<-gate
		return scanner.ProbeResult{Address: target}, nil
	}
	body := `{"action":"start","subnet":"192.168.1.0/24","source":"192.168.1.2","interface_index":22}`
	if code, b := do(t, "POST", url, s.token, body); code != 202 {
		t.Fatal(code, b)
	}
	if code, b := do(t, "POST", url, s.token, body); code != 409 {
		t.Fatal(code, b)
	}
	if code, b := do(t, "POST", url, s.token, `{"action":"cancel"}`); code != 200 {
		t.Fatal(code, b)
	}
	s.scan.mu.Lock()
	job := s.scan.job
	s.scan.mu.Unlock()
	// Release the at most eight already in-flight calls. No new scan is started.
	for i := 0; i < 8; i++ {
		select {
		case gate <- struct{}{}:
		case <-time.After(20 * time.Millisecond):
		}
	}
	v := awaitScan(t, s, url)
	if v.State != "cancelled" || v.Completed > 16 {
		t.Fatal(v)
	}
	job.Wait()
}
