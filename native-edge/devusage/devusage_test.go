package devusage

import (
	"path/filepath"
	"testing"
	"time"
)

func pkt(src, dst [4]byte, proto byte, sport, dport uint16, size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	p[2], p[3] = byte(size>>8), byte(size)
	p[9] = proto
	copy(p[12:], src[:])
	copy(p[16:], dst[:])
	p[20], p[21], p[22], p[23] = byte(sport>>8), byte(sport), byte(dport>>8), byte(dport)
	return p
}

var (
	dev = [4]byte{10, 77, 0, 9}
	srv = [4]byte{93, 184, 216, 34}
)

func clocked(start time.Time) (*Tracker, *time.Time) {
	tr := New()
	now := start
	tr.now = func() time.Time { return now }
	return tr, &now
}

func snap(tr *Tracker) map[string]any { return tr.Snapshot()["10.77.0.9"].(map[string]any) }

func TestBreakdownAndTotals(t *testing.T) {
	tr, _ := clocked(time.Unix(1_700_000_000, 0))
	tr.Record(dev, true, pkt(dev, srv, 6, 50000, 443, 1000))
	tr.Record(dev, false, pkt(srv, dev, 6, 443, 50000, 1500))
	tr.Record(dev, true, pkt(dev, srv, 17, 40000, 3074, 200))
	d := snap(tr)
	if d["up_bytes"].(uint64) != 1200 || d["down_bytes"].(uint64) != 1500 {
		t.Fatalf("totals %v %v", d["up_bytes"], d["down_bytes"])
	}
	svcs := d["services"].([]*row)
	if len(svcs) != 2 || svcs[0].Service != "HTTPS" || svcs[0].Up != 1000 || svcs[0].Down != 1500 {
		t.Fatalf("services %+v", svcs)
	}
	if svcs[1].Service != "Xbox / Call of Duty" {
		t.Fatalf("second service %q", svcs[1].Service)
	}
}

func TestRateAndPeakReadZeroWhenQuiet(t *testing.T) {
	tr, now := clocked(time.Unix(1_700_000_000, 0))
	tr.Record(dev, true, pkt(dev, srv, 6, 1, 443, 1000))
	*now = now.Add(6 * time.Second)
	tr.Record(dev, true, pkt(dev, srv, 6, 1, 443, 1000))
	d := snap(tr)
	if d["up_bps"].(float64) <= 0 || d["peak_up_bps"].(float64) <= 0 {
		t.Fatalf("expected a rate: %v", d)
	}
	*now = now.Add(time.Minute)
	d = snap(tr)
	if d["up_bps"].(float64) != 0 {
		t.Fatalf("quiet device still reads %v", d["up_bps"])
	}
	if d["peak_up_bps"].(float64) <= 0 {
		t.Fatal("peak should survive quiet")
	}
}

func TestHistoryPerMinutePersistsAndExpires(t *testing.T) {
	tr, now := clocked(time.Unix(1_700_000_000, 0))
	for i := 0; i < 3; i++ {
		tr.Record(dev, false, pkt(srv, dev, 6, 443, 1, 500))
		*now = now.Add(time.Minute)
	}
	path := filepath.Join(t.TempDir(), "u.json")
	if err := tr.Save(path); err != nil {
		t.Fatal(err)
	}
	t2, _ := clocked(*now)
	t2.Load(path)
	h := snap(t2)["history"].([][3]uint64)
	if len(h) != 3 || h[0][2] != 500 {
		t.Fatalf("history %v", h)
	}
	t3, _ := clocked(now.Add(25 * time.Hour))
	t3.Load(path)
	if h := snap(t3)["history"].([][3]uint64); len(h) != 0 {
		t.Fatalf("stale history kept: %v", h)
	}
}

func TestJunkIgnoredAndFragmentsCountedWithoutPort(t *testing.T) {
	tr, _ := clocked(time.Unix(1_700_000_000, 0))
	tr.Record(dev, true, []byte{1, 2, 3})
	if len(tr.Snapshot()) != 0 {
		t.Fatal("junk created a device")
	}
	f := pkt(dev, srv, 17, 1, 53, 100)
	f[7] = 0x10 // non-first fragment: the bytes are not ports
	tr.Record(dev, true, f)
	d := snap(tr)
	if d["up_bytes"].(uint64) != 100 {
		t.Fatalf("fragment not counted: %v", d["up_bytes"])
	}
	if p := d["ports"].([]row); len(p) != 1 || p[0].Port != 0 {
		t.Fatalf("fragment attributed a port: %+v", p)
	}
}

func TestPortTableIsBounded(t *testing.T) {
	tr, _ := clocked(time.Unix(1_700_000_000, 0))
	for port := 1; port <= 500; port++ {
		tr.Record(dev, true, pkt(dev, srv, 6, 1, uint16(port), 100))
	}
	tr.mu.Lock()
	n := len(tr.devs[dev].Ports)
	tr.mu.Unlock()
	if n > maxPorts {
		t.Fatalf("%d ports tracked", n)
	}
}

func portRows(d map[string]any) map[uint16]row {
	out := map[uint16]row{}
	for _, r := range d["ports"].([]row) {
		out[r.Port] = r
	}
	return out
}

func TestPortsReportRecency(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	tr, now := clocked(start)
	tr.Record(dev, true, pkt(dev, srv, 6, 50000, 443, 1000))
	tr.Record(dev, true, pkt(dev, srv, 17, 40000, 3478, 100))
	*now = start.Add(30 * time.Second)
	tr.Record(dev, true, pkt(dev, srv, 17, 40000, 3478, 100))
	d := snap(tr)
	rows := portRows(d)
	if !rows[3478].Active || rows[443].Active {
		t.Fatalf("3478 should be active and 443 idle: %+v", rows)
	}
	if rows[443].LastSeen != start.Unix() || rows[3478].LastSeen != now.Unix() {
		t.Fatalf("last seen: %+v", rows)
	}
	if d["active_ports"].(int) != 1 {
		t.Fatalf("active_ports = %v", d["active_ports"])
	}
	if first := d["ports"].([]row)[0]; first.Port != 3478 {
		t.Fatalf("active ports must sort first even with fewer bytes: %+v", d["ports"])
	}
	*now = now.Add(activeWindow + time.Second)
	if d := snap(tr); d["active_ports"].(int) != 0 {
		t.Fatalf("nothing sent for %v: %v", activeWindow, d["active_ports"])
	}
}

// A small port that just started must survive the display cut even when twenty busier idle ports exist.
func TestActivePortIsNeverCutFromTheList(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	tr, now := clocked(start)
	for port := 1000; port < 1030; port++ {
		tr.Record(dev, true, pkt(dev, srv, 6, 1, uint16(port), 1400))
	}
	*now = start.Add(time.Minute)
	tr.Record(dev, true, pkt(dev, srv, 17, 1, 3478, 60))
	d := snap(tr)
	if rows := portRows(d); !rows[3478].Active || len(d["ports"].([]row)) != 20 {
		t.Fatalf("active port missing or list not bounded: %d rows", len(d["ports"].([]row)))
	}
}

func TestEvictionPrefersIdlePorts(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	tr, now := clocked(start)
	for port := 1; port <= maxPorts; port++ {
		tr.Record(dev, true, pkt(dev, srv, 6, 1, uint16(port), 1000))
	}
	*now = start.Add(time.Minute)
	for port := 1; port <= 10; port++ { // ten ports stay active, with the fewest bytes
		tr.Record(dev, true, pkt(dev, srv, 6, 1, uint16(port), 50))
	}
	tr.Record(dev, true, pkt(dev, srv, 6, 1, 9000, 40)) // forces an eviction
	tr.Record(dev, true, pkt(dev, srv, 6, 1, 9001, 40)) // and another
	tr.mu.Lock()
	ports := tr.devs[dev].Ports
	for _, port := range []uint16{1, 5, 10, 9000, 9001} {
		if ports[portKey{"tcp", port}] == nil {
			tr.mu.Unlock()
			t.Fatalf("active port %d was evicted", port)
		}
	}
	n := len(ports)
	tr.mu.Unlock()
	if n > maxPorts {
		t.Fatalf("%d ports tracked", n)
	}
}
