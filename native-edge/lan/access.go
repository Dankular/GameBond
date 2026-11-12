package lan

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

// Access modes for devices that are not in lan_devices.
const (
	AccessClosed = "closed" // only configured and accepted devices; attempts are logged silently
	AccessAsk    = "ask"    // an unknown device raises a notification; accept or decline
	AccessAuto   = "auto"   // an unknown device is accepted at once (private networks)
)

// AccessEntry is one accepted or blocked device.
type AccessEntry struct {
	MAC   string `json:"mac"`
	Name  string `json:"name"`
	IP    string `json:"ip,omitempty"`
	Added int64  `json:"added,omitempty"`
}

// Access is the allow/block list shared by the client and the GUI (lan-access.json).
// The blacklist always wins over the mode.
type Access struct {
	Mode     string        `json:"mode"`
	Accepted []AccessEntry `json:"accepted"`
	Blocked  []AccessEntry `json:"blocked"`
}

// Pending is a device that tried to get an address and is waiting for a decision
// (lan-pending.json, written by the client).
type Pending struct {
	MAC      string `json:"mac"`
	Hostname string `json:"hostname,omitempty"`
	First    int64  `json:"first"`
	Last     int64  `json:"last"`
	Attempts int    `json:"attempts"`
}

// NormMAC returns the canonical lower-case colon form.
func NormMAC(s string) (string, error) {
	m, err := ParseMAC(s)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]), nil
}

func (a *Access) find(list []AccessEntry, mac string) int {
	for i, e := range list {
		if strings.EqualFold(e.MAC, mac) {
			return i
		}
	}
	return -1
}

func (a *Access) IsBlocked(mac string) bool  { return a.find(a.Blocked, mac) >= 0 }
func (a *Access) IsAccepted(mac string) bool { return a.find(a.Accepted, mac) >= 0 }

// Accept adds the device and removes it from the blacklist.
func (a *Access) Accept(e AccessEntry) {
	a.Unblock(e.MAC)
	if i := a.find(a.Accepted, e.MAC); i >= 0 {
		a.Accepted[i].Name = e.Name
		return
	}
	e.Added = time.Now().Unix()
	a.Accepted = append(a.Accepted, e)
}

// Block adds the device to the blacklist and removes any acceptance.
func (a *Access) Block(e AccessEntry) {
	a.Remove(e.MAC)
	if a.find(a.Blocked, e.MAC) < 0 {
		e.Added, e.IP = time.Now().Unix(), ""
		a.Blocked = append(a.Blocked, e)
	}
}

func (a *Access) Unblock(mac string) {
	if i := a.find(a.Blocked, mac); i >= 0 {
		a.Blocked = append(a.Blocked[:i], a.Blocked[i+1:]...)
	}
}

func (a *Access) Remove(mac string) {
	if i := a.find(a.Accepted, mac); i >= 0 {
		a.Accepted = append(a.Accepted[:i], a.Accepted[i+1:]...)
	}
}

func (a *Access) normalise() {
	if a.Mode != AccessAsk && a.Mode != AccessAuto {
		a.Mode = AccessClosed
	}
	if a.Accepted == nil {
		a.Accepted = []AccessEntry{}
	}
	if a.Blocked == nil {
		a.Blocked = []AccessEntry{}
	}
}

// LoadAccess reads the file; a missing or damaged file is the closed default.
func LoadAccess(path string) Access {
	var a Access
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &a)
	}
	a.normalise()
	return a
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// UpdateAccess applies fn to the current file under a lock file, so the client and the
// GUI never overwrite each other's change.
func UpdateAccess(path string, fn func(*Access) error) error {
	lock := path + ".lock"
	var f *os.File
	var err error
	for i := 0; i < 100; i++ {
		f, err = os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			break
		}
		if st, serr := os.Stat(lock); serr == nil && time.Since(st.ModTime()) > 5*time.Second {
			os.Remove(lock) // a crashed writer
			continue
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return errors.New("access list is busy")
	}
	f.Close()
	defer os.Remove(lock)
	a := LoadAccess(path)
	if err := fn(&a); err != nil {
		return err
	}
	a.normalise()
	return writeJSON(path, a)
}

// LoadPending reads the client's pending list, newest first.
func LoadPending(path string) []Pending {
	var p []Pending
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	if p == nil {
		p = []Pending{}
	}
	sort.Slice(p, func(i, j int) bool { return p[i].Last > p[j].Last })
	return p
}

func SavePending(path string, p []Pending) error { return writeJSON(path, p) }

// DefaultDeviceName names a device by its hostname, or by the end of its MAC.
func DefaultDeviceName(hostname, mac string) string {
	h := strings.TrimSpace(hostname)
	if h == "" {
		if len(mac) >= 8 {
			h = "Device " + strings.ReplaceAll(mac[len(mac)-8:], ":", "")
		} else {
			h = "Device"
		}
	}
	var b strings.Builder
	for _, r := range h {
		if r < 0x80 && (r == ' ' || r == '.' || r == '_' || r == '(' || r == ')' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			b.WriteRune(r)
		}
	}
	if b.Len() > 32 {
		return b.String()[:32]
	}
	if b.Len() == 0 {
		return "Device"
	}
	return b.String()
}

// NextFreeIP returns the first unused address from .10 up in the client's /24, or "".
func NextFreeIP(client netip.Addr, taken []string) string {
	used := map[string]bool{client.String(): true}
	for _, t := range taken {
		used[t] = true
	}
	b := client.As4()
	for i := 10; i < 255; i++ {
		ip := netip.AddrFrom4([4]byte{b[0], b[1], b[2], byte(i)}).String()
		if !used[ip] {
			return ip
		}
	}
	return ""
}
