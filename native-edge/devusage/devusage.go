// Package devusage accounts the traffic of tunnel-routed LAN devices: live rate, totals,
// a protocol/port/service breakdown and a per-minute history. It sees only packets that
// cross the tunnel; devices that stay on the local network are not visible to it.
package devusage

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	historyMinutes = 24 * 60
	maxPorts       = 64 // per device; the smallest entry is evicted past this
	maxRemotes     = 256
	rateWindow     = 5 * time.Second
	// activeWindow is how recently a port must have carried a packet to count as active.
	activeWindow = 10 * time.Second
)

// Service names a well-known remote port. It is a label inferred from the port, not deep inspection.
func Service(proto string, port uint16) string {
	switch port {
	case 53:
		return "DNS"
	case 80, 8080:
		return "HTTP"
	case 443:
		if proto == "udp" {
			return "QUIC / HTTP3"
		}
		return "HTTPS"
	case 123:
		return "NTP"
	case 22:
		return "SSH"
	case 3478, 3479, 3480:
		return "PlayStation / STUN"
	case 3074:
		return "Xbox / Call of Duty"
	case 5222, 5223:
		return "Messaging / push"
	case 993, 995, 587, 465:
		return "Mail"
	case 1935:
		return "Streaming (RTMP)"
	case 27015, 27036:
		return "Steam"
	case 51820:
		return "WireGuard"
	}
	if proto == "udp" && port > 3074 && port <= 3100 {
		return "Game traffic"
	}
	return ""
}

type bucket struct {
	Minute int64  `json:"m"` // unix minute
	Up     uint64 `json:"u"`
	Down   uint64 `json:"d"`
}

type portKey struct {
	Proto string
	Port  uint16
}

type portStat struct {
	Up, Down uint64
	Packets  uint64
	Last     time.Time // when the port last carried a packet
}

type device struct {
	First, Last  time.Time
	Up, Down     uint64
	PktUp, PktDn uint64
	Ports        map[portKey]*portStat
	Remotes      map[[4]byte]uint64
	History      []bucket
	rateAt       time.Time
	rateUp       uint64 // bytes in the current window
	rateDown     uint64
	lastUp       float64 // bits per second over the last closed window
	lastDown     float64
	lastRateAt   time.Time
	peakUp       float64
	peakDown     float64
}

// Tracker is safe for concurrent use.
type Tracker struct {
	mu   sync.Mutex
	devs map[[4]byte]*device
	now  func() time.Time
}

func New() *Tracker { return &Tracker{devs: map[[4]byte]*device{}, now: time.Now} }

// Record accounts one IPv4 packet for the device. outbound is device -> tunnel.
func (t *Tracker) Record(dev [4]byte, outbound bool, p []byte) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	hl := int(p[0]&15) * 4
	if hl < 20 || len(p) < hl {
		return
	}
	size := uint64(binary.BigEndian.Uint16(p[2:]))
	if size == 0 || size > uint64(len(p)) {
		size = uint64(len(p))
	}
	off := 16 // remote is the destination when the device sends
	if !outbound {
		off = 12
	}
	var remote [4]byte
	copy(remote[:], p[off:off+4])
	proto := "other"
	var port uint16
	switch p[9] {
	case 6, 17:
		proto = "tcp"
		if p[9] == 17 {
			proto = "udp"
		}
		// Only the first fragment carries ports.
		if binary.BigEndian.Uint16(p[6:])&0x1FFF == 0 && len(p) >= hl+4 {
			po := hl + 2 // destination port when the device sends
			if !outbound {
				po = hl // source port of the remote
			}
			port = binary.BigEndian.Uint16(p[po:])
		}
	case 1:
		proto = "icmp"
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.devs[dev]
	if d == nil {
		d = &device{First: now, rateAt: now, Ports: map[portKey]*portStat{}, Remotes: map[[4]byte]uint64{}}
		t.devs[dev] = d
	}
	d.Last = now
	if el := now.Sub(d.rateAt); el >= rateWindow {
		d.lastUp, d.lastDown = float64(d.rateUp)*8/el.Seconds(), float64(d.rateDown)*8/el.Seconds()
		d.lastRateAt = now
		d.peakUp, d.peakDown = max(d.peakUp, d.lastUp), max(d.peakDown, d.lastDown)
		d.rateAt, d.rateUp, d.rateDown = now, 0, 0
	}
	minute := now.Unix() / 60
	if n := len(d.History); n == 0 || d.History[n-1].Minute != minute {
		d.History = append(d.History, bucket{Minute: minute})
		if len(d.History) > historyMinutes {
			d.History = d.History[len(d.History)-historyMinutes:]
		}
	}
	b := &d.History[len(d.History)-1]
	k := portKey{proto, port}
	ps := d.Ports[k]
	if ps == nil {
		if len(d.Ports) >= maxPorts {
			evict(d.Ports, now)
		}
		ps = &portStat{}
		d.Ports[k] = ps
	}
	ps.Packets++
	ps.Last = now
	if _, seen := d.Remotes[remote]; seen || len(d.Remotes) < maxRemotes {
		d.Remotes[remote] += size
	}
	if outbound {
		d.Up += size
		d.PktUp++
		b.Up += size
		ps.Up += size
		d.rateUp += size
	} else {
		d.Down += size
		d.PktDn++
		b.Down += size
		ps.Down += size
		d.rateDown += size
	}
}

// evict drops the smallest port that is no longer active; only when every port is active does it drop
// the smallest overall, so a port that has just started is not the first thing to disappear.
func evict(m map[portKey]*portStat, now time.Time) {
	var worst portKey
	least, found := ^uint64(0), false
	for pass := 0; pass < 2 && !found; pass++ {
		for k, v := range m {
			if pass == 0 && now.Sub(v.Last) <= activeWindow {
				continue
			}
			if s := v.Up + v.Down; s < least {
				least, worst, found = s, k, true
			}
		}
	}
	delete(m, worst)
}

// Snapshot returns one entry per device keyed by dotted tunnel IP.
func (t *Tracker) Snapshot() map[string]any {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]any{}
	for ip, d := range t.devs {
		out[ipString(ip)] = d.view(now)
	}
	return out
}

func ipString(ip [4]byte) string { return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]) }

type row struct {
	Proto   string `json:"proto,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Service string `json:"service"`
	Up      uint64 `json:"up_bytes"`
	Down    uint64 `json:"down_bytes"`
	Packets uint64 `json:"packets"`
	// Only set on port rows: when the port last carried a packet (unix seconds) and whether that was
	// within activeWindow of the snapshot.
	LastSeen int64 `json:"last_seen,omitempty"`
	Active   bool  `json:"active,omitempty"`
}

func (d *device) view(now time.Time) map[string]any {
	// A device that went quiet reads zero, not its last busy window.
	upBps, downBps := d.lastUp, d.lastDown
	if now.Sub(d.lastRateAt) > 2*rateWindow {
		upBps, downBps = 0, 0
	}
	ports := make([]row, 0, len(d.Ports))
	for k, v := range d.Ports {
		ports = append(ports, row{k.Proto, k.Port, Service(k.Proto, k.Port), v.Up, v.Down, v.Packets, v.Last.Unix(), now.Sub(v.Last) <= activeWindow})
	}
	// Active ports first, then by traffic.
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Active != ports[j].Active {
			return ports[i].Active
		}
		return ports[i].Up+ports[i].Down > ports[j].Up+ports[j].Down
	})
	active := 0
	for _, r := range ports {
		if r.Active {
			active++
		}
	}
	// Per-service totals for the "apps" breakdown; unlabelled ports group by protocol.
	// Built from every port, before the port list is cut for display.
	byService := map[string]*row{}
	for _, r := range ports {
		name := r.Service
		if name == "" {
			name = "Other " + r.Proto
		}
		s := byService[name]
		if s == nil {
			s = &row{Service: name}
			byService[name] = s
		}
		s.Up, s.Down, s.Packets = s.Up+r.Up, s.Down+r.Down, s.Packets+r.Packets
	}
	services := make([]*row, 0, len(byService))
	for _, s := range byService {
		services = append(services, s)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Up+services[i].Down > services[j].Up+services[j].Down })
	// The list is cut for display, but never through an active port (up to a sanity cap).
	if limit := min(max(20, active), 40); len(ports) > limit {
		ports = ports[:limit]
	}
	type remote struct {
		IP    string `json:"ip"`
		Bytes uint64 `json:"bytes"`
	}
	remotes := make([]remote, 0, len(d.Remotes))
	for ip, n := range d.Remotes {
		remotes = append(remotes, remote{ipString(ip), n})
	}
	sort.Slice(remotes, func(i, j int) bool { return remotes[i].Bytes > remotes[j].Bytes })
	if len(remotes) > 10 {
		remotes = remotes[:10]
	}
	// One [unix seconds, up bytes, down bytes] triple per minute: the status file is rewritten
	// every second, so the 24 h history is kept compact.
	history := make([][3]uint64, 0, len(d.History))
	for _, b := range d.History {
		history = append(history, [3]uint64{uint64(b.Minute * 60), b.Up, b.Down})
	}
	return map[string]any{
		"first_seen": d.First.Unix(), "last_seen": d.Last.Unix(),
		"up_bytes": d.Up, "down_bytes": d.Down, "up_packets": d.PktUp, "down_packets": d.PktDn,
		"up_bps": upBps, "down_bps": downBps, "peak_up_bps": max(d.peakUp, upBps), "peak_down_bps": max(d.peakDown, downBps),
		"ports": ports, "active_ports": active, "services": services, "remotes": remotes, "history": history,
	}
}

type saved struct {
	Version int                    `json:"version"`
	Devices map[string]savedDevice `json:"devices"`
}

type savedDevice struct {
	First   int64    `json:"first"`
	Up      uint64   `json:"up"`
	Down    uint64   `json:"down"`
	History []bucket `json:"history"`
}

// Save writes totals and history (not the port breakdown, which is per session) to path.
func (t *Tracker) Save(path string) error {
	t.mu.Lock()
	s := saved{Version: 1, Devices: map[string]savedDevice{}}
	for ip, d := range t.devs {
		s.Devices[ipString(ip)] = savedDevice{d.First.Unix(), d.Up, d.Down, append([]bucket(nil), d.History...)}
	}
	t.mu.Unlock()
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load restores saved totals and history, dropping buckets older than 24 h. A missing or
// corrupt file is not an error: the tracker starts empty.
func (t *Tracker) Load(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var s saved
	if json.Unmarshal(data, &s) != nil || s.Version != 1 {
		return
	}
	now := t.now()
	cutoff := now.Unix()/60 - historyMinutes
	t.mu.Lock()
	defer t.mu.Unlock()
	for text, sd := range s.Devices {
		var ip [4]byte
		if _, err := fmt.Sscanf(text, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]); err != nil {
			continue
		}
		d := &device{First: time.Unix(sd.First, 0), rateAt: now, Up: sd.Up, Down: sd.Down,
			Ports: map[portKey]*portStat{}, Remotes: map[[4]byte]uint64{}}
		for _, b := range sd.History {
			if b.Minute > cutoff {
				d.History = append(d.History, b)
			}
		}
		t.devs[ip] = d
	}
}
