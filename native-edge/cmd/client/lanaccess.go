package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/lan"
)

// lanAccess lets devices that are not in lan_devices ask for an address. A DHCP request
// from an unknown MAC is checked against the blacklist, then the mode: closed (ignore,
// but list the attempt), ask (raise a notification in the GUI) or auto (accept at once).
// Accepted devices become gateways without a restart. The lists live in lan-access.json,
// shared with the GUI; the client owns lan-pending.json.
type lanAccess struct {
	accessPath, pendingPath string
	mtime                   time.Time
	cur                     lan.Access
	seen                    map[string]*lan.Pending
	fresh                   map[string]string // mac -> hostname, queued by the frame hook
	dirty                   bool
	savedAt                 time.Time
	blockedAttempts         uint64
	dynamic                 []lan.DeviceConfig
	fmu                     sync.Mutex // guards fresh alone: the frame hook holds an adapter lock
}

const maxPending = 32

// useAccess turns the feature on; dir is the runtime directory.
func (m *lanManager) useAccess(dir string) {
	if m == nil || dir == "" {
		return
	}
	m.access = &lanAccess{accessPath: filepath.Join(dir, "lan-access.json"), pendingPath: filepath.Join(dir, "lan-pending.json"),
		seen: map[string]*lan.Pending{}, fresh: map[string]string{}}
	for _, p := range lan.LoadPending(m.access.pendingPath) {
		p := p
		m.access.seen[p.MAC] = &p
	}
	m.access.cur = lan.LoadAccess(m.access.accessPath)
	if m.shared != nil {
		m.shared.unknown = m.noteUnknown
	}
}

// noteUnknown runs under the adapter lock: it only queues the observation.
func (m *lanManager) noteUnknown(src [6]byte, frame []byte) {
	if m.access == nil {
		return
	}
	mac := fmtMAC(src)
	host := dhcpHostname(frame)
	m.access.fmu.Lock()
	if len(m.access.fresh) < 64 {
		m.access.fresh[mac] = host
	}
	m.access.fmu.Unlock()
}

// dhcpHostname reads option 12 from a DHCP request frame.
func dhcpHostname(f []byte) string {
	if len(f) < 14+20+8+240 {
		return ""
	}
	ihl := int(f[14]&0x0f) * 4
	o := 14 + ihl + 8 + 240
	for o+1 < len(f) {
		code := f[o]
		if code == 255 {
			break
		}
		if code == 0 {
			o++
			continue
		}
		n := int(f[o+1])
		if o+2+n > len(f) {
			break
		}
		if code == 12 {
			name := lan.DefaultDeviceName(string(f[o+2:o+2+n]), "")
			if name == "Device" {
				return ""
			}
			return name
		}
		o += 2 + n
	}
	return ""
}

// processAccess runs once a second from maintain.
func (m *lanManager) processAccess() {
	a := m.access
	if a == nil {
		return
	}
	if st, err := os.Stat(a.accessPath); err == nil && !st.ModTime().Equal(a.mtime) {
		a.mtime = st.ModTime()
		a.cur = lan.LoadAccess(a.accessPath)
	}
	a.fmu.Lock()
	fresh := a.fresh
	a.fresh = map[string]string{}
	a.fmu.Unlock()
	now := time.Now().Unix()
	for mac, host := range fresh {
		switch {
		case a.cur.IsBlocked(mac):
			a.blockedAttempts++
		case a.cur.IsAccepted(mac) || m.configured(mac):
		case a.cur.Mode == lan.AccessAuto:
			m.autoAccept(mac, host)
		default:
			p := a.seen[mac]
			if p == nil {
				if len(a.seen) >= maxPending {
					continue
				}
				p = &lan.Pending{MAC: mac, First: now}
				a.seen[mac] = p
			}
			p.Last, p.Hostname = now, host
			p.Attempts++
			a.dirty = true
		}
	}
	for mac, p := range a.seen { // decided in the GUI, or gone quiet for a day
		if a.cur.IsAccepted(mac) || a.cur.IsBlocked(mac) || now-p.Last > 86400 {
			delete(a.seen, mac)
			a.dirty = true
		}
	}
	if a.dirty && time.Since(a.savedAt) > 2*time.Second {
		list := make([]lan.Pending, 0, len(a.seen))
		for _, p := range a.seen {
			list = append(list, *p)
		}
		if lan.SavePending(a.pendingPath, list) == nil {
			a.dirty, a.savedAt = false, time.Now()
		}
	}
	m.syncDynamic()
}

func (m *lanManager) configured(mac string) bool {
	for _, d := range m.devices {
		if strings.EqualFold(d.DeviceMAC, mac) {
			return true
		}
	}
	return false
}

func (m *lanManager) autoAccept(mac, host string) {
	a := m.access
	var taken []string
	for _, d := range m.all() {
		taken = append(taken, d.TunnelIP.String())
	}
	for _, e := range a.cur.Accepted {
		taken = append(taken, e.IP)
	}
	ip := lan.NextFreeIP(m.client, taken)
	if ip == "" {
		return
	}
	_ = lan.UpdateAccess(a.accessPath, func(l *lan.Access) error {
		if !l.IsBlocked(mac) && !l.IsAccepted(mac) {
			l.Accept(lan.AccessEntry{MAC: mac, Name: lan.DefaultDeviceName(host, mac), IP: ip})
		}
		return nil
	})
	a.cur = lan.LoadAccess(a.accessPath)
}

// syncDynamic makes the running gateways match the accepted list: devices are added on
// the first adapter's interface and removed when the GUI removes or blocks them.
func (m *lanManager) syncDynamic() {
	a := m.access
	if len(m.devices) == 0 {
		return
	}
	tpl := m.devices[0]
	want := map[string]bool{}
	names := map[string]bool{}
	for _, d := range m.devices {
		names[strings.ToLower(d.Name)] = true
	}
	var next []lan.DeviceConfig
	for _, e := range a.cur.Accepted {
		ip, err := netip.ParseAddr(e.IP)
		if err != nil || m.configured(e.MAC) {
			continue
		}
		name := e.Name
		for n := 2; names[strings.ToLower(name)]; n++ {
			name = e.Name + " " + strconv.Itoa(n)
		}
		names[strings.ToLower(name)] = true
		want[strings.ToLower(e.MAC)] = true
		next = append(next, lan.DeviceConfig{Name: name, TunnelIP: ip, InterfaceID: tpl.InterfaceID, InterfaceName: tpl.InterfaceName,
			InterfaceIndex: tpl.InterfaceIndex, DeviceMAC: e.MAC, DNS: tpl.DNS})
	}
	m.mu.Lock()
	for _, old := range a.dynamic {
		if want[strings.ToLower(old.DeviceMAC)] {
			continue
		}
		if rg := m.gws[old.Name]; rg != nil {
			rg.cancel()
			rg.io.Close()
			delete(m.gws, old.Name)
			if ip := old.TunnelIP.As4(); m.byIP[ip] == rg.gw {
				delete(m.byIP, ip)
			}
		}
		delete(m.errs, old.Name)
	}
	a.dynamic = next
	m.mu.Unlock()
}

// all is the configured devices plus the accepted ones.
func (m *lanManager) all() []lan.DeviceConfig {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.access == nil || len(m.access.dynamic) == 0 {
		return m.devices
	}
	out := make([]lan.DeviceConfig, 0, len(m.devices)+len(m.access.dynamic))
	return append(append(out, m.devices...), m.access.dynamic...)
}

// accessStatus is the lan_access entry of the status document.
func (m *lanManager) accessStatus() any {
	if m == nil || m.access == nil {
		return nil
	}
	a := m.access
	m.mu.Lock()
	defer m.mu.Unlock()
	pending := make([]lan.Pending, 0, len(a.seen))
	for _, p := range a.seen {
		pending = append(pending, *p)
	}
	return map[string]any{"mode": a.cur.Mode, "pending": pending, "accepted": len(a.cur.Accepted), "blocked": len(a.cur.Blocked), "blocked_attempts": a.blockedAttempts}
}
