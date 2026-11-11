package lan

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Lease is one row of the DHCP lease table: which MAC holds which tunnel address.
type Lease struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Leased  bool   `json:"leased"`  // a DHCP lease is held (false: static address or released)
	Granted int64  `json:"granted"` // unix seconds of the last ACK; 0 when never leased by DHCP
	Expires int64  `json:"expires"` // unix seconds; 0 when never leased by DHCP
}

// Active reports whether the lease is held and unexpired at now.
func (l Lease) Active(now time.Time) bool {
	return l.Leased && (l.Expires == 0 || now.Unix() < l.Expires)
}

// LeaseTable persists leases so a restart neither forgets which device holds an
// address nor waits for the device to speak first. Writes are atomic (temp file
// and rename) and only happen when a row actually changes. A missing or corrupt
// file starts an empty table: the table is an optimisation, never a dependency.
type LeaseTable struct {
	mu   sync.Mutex
	path string
	rows map[string]Lease
	// WriteErrors counts failed saves; the in-memory table stays authoritative.
	WriteErrors uint64
}

func leaseKey(name string, ip netip.Addr) string { return name + "|" + ip.String() }

// OpenLeaseTable loads the table at path. An empty path gives a memory-only table.
func OpenLeaseTable(path string) *LeaseTable {
	t := &LeaseTable{path: path, rows: map[string]Lease{}}
	if path == "" {
		return t
	}
	var rows []Lease
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &rows) == nil {
		for _, r := range rows {
			if r.Name != "" && r.IP != "" && r.MAC != "" {
				t.rows[r.Name+"|"+r.IP] = r
			}
		}
	}
	return t
}

// Get returns the row for a device.
func (t *LeaseTable) Get(name string, ip netip.Addr) (Lease, bool) {
	if t == nil {
		return Lease{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.rows[leaseKey(name, ip)]
	return l, ok
}

// Put stores a row and saves the table when the row changed.
func (t *LeaseTable) Put(l Lease) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	key := l.Name + "|" + l.IP
	if t.rows[key] == l {
		return
	}
	t.rows[key] = l
	t.saveLocked()
}

// Rows lists the table ordered by address.
func (t *LeaseTable) Rows() []Lease {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Lease, 0, len(t.rows))
	for _, r := range t.rows {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func (t *LeaseTable) saveLocked() {
	if t.path == "" {
		return
	}
	rows := make([]Lease, 0, len(t.rows))
	for _, r := range t.rows {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].IP < rows[j].IP })
	b, err := json.MarshalIndent(rows, "", " ")
	if err != nil {
		t.WriteErrors++
		return
	}
	tmp := t.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
		t.WriteErrors++
		return
	}
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		t.WriteErrors++
		return
	}
	if err := os.Rename(tmp, t.path); err != nil {
		t.WriteErrors++
	}
}
