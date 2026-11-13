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
	historyHours   = 35 * 24 // hourly totals kept for the week and month views
	maxPorts       = 64      // per device; the smallest entry is evicted past this
	maxRemotes     = 256
	rateWindow     = 5 * time.Second
	// activeWindow is how recently a port must have carried a packet to count as active.
	activeWindow = 10 * time.Second
	// maxSyns bounds the handshakes awaiting an answer per device; synTimeout is how long one is kept.
	maxSyns       = 128
	synTimeout    = 10 * time.Second
	maxRTTSamples = 64 // per device per minute
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

// Category groups a remote port into a coarse traffic class. Like Service it is inferred from the port
// alone (this is not deep packet inspection), so anything on an unlisted port is "Other".
func Category(proto string, port uint16) string {
	switch port {
	case 80, 443, 8080, 8443:
		return "Web"
	case 53:
		return "DNS"
	case 123:
		return "Network services"
	case 22, 3389, 5900:
		return "Remote access"
	case 51820, 1194, 500, 4500:
		return "VPN"
	case 5222, 5223:
		return "Messaging"
	case 993, 995, 587, 465, 143, 110, 25:
		return "Mail"
	case 1935:
		return "Streaming"
	case 3074, 3478, 3479, 3480, 27015, 27036:
		return "Gaming"
	}
	if proto == "udp" && port > 3074 && port <= 3100 {
		return "Gaming"
	}
	if proto == "icmp" {
		return "Network services"
	}
	return "Other"
}

// categoryRow is one traffic class of a device in a snapshot.
type categoryRow struct {
	Category string `json:"category"`
	Up       uint64 `json:"up_bytes"`
	Down     uint64 `json:"down_bytes"`
}

// hourBucket is one hour of a device's traffic; the week and month views are sums of these.
type hourBucket struct {
	Hour int64  `json:"h"` // unix hour
	Up   uint64 `json:"u,omitempty"`
	Down uint64 `json:"d,omitempty"`
}

type bucket struct {
	Minute int64  `json:"m"` // unix minute
	Up     uint64 `json:"u"`
	Down   uint64 `json:"d"`
	RTT    uint32 `json:"r,omitempty"` // median TCP handshake time seen this minute, in tenths of a millisecond
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

type synKey struct {
	Remote       [4]byte
	RPort, LPort uint16
}

type synState struct {
	At   time.Time
	Retx bool // the SYN was sent again: an answer cannot be matched to one attempt, so it gives no sample
}

type device struct {
	First, Last  time.Time
	Up, Down     uint64
	PktUp, PktDn uint64
	Ports        map[portKey]*portStat
	Remotes      map[[4]byte]uint64
	History      []bucket
	Hours        []hourBucket
	rateAt       time.Time
	rateUp       uint64 // bytes in the current window
	rateDown     uint64
	lastUp       float64 // bits per second over the last closed window
	lastDown     float64
	lastRateAt   time.Time
	peakUp       float64
	peakDown     float64
	syns         map[synKey]synState
	rttMinute    int64
	rttSamples   []uint32 // tenths of a ms, this minute
	lastRTT      uint32
	lastRTTAt    time.Time
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
	var port, lport uint16
	tcpFlags := -1
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
			lo := hl // the device's own port: the source when it sends, the destination when it receives
			if !outbound {
				lo = hl + 2
			}
			lport = binary.BigEndian.Uint16(p[lo:])
			if proto == "tcp" && len(p) >= hl+14 {
				tcpFlags = int(p[hl+13])
			}
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
	hour := now.Unix() / 3600
	if n := len(d.Hours); n == 0 || d.Hours[n-1].Hour != hour {
		d.Hours = append(d.Hours, hourBucket{Hour: hour})
		if len(d.Hours) > historyHours {
			d.Hours = d.Hours[len(d.Hours)-historyHours:]
		}
	}
	hb := &d.Hours[len(d.Hours)-1]
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
	if tcpFlags >= 0 {
		d.handshake(now, remote, port, lport, outbound, tcpFlags, b)
	}
	if _, seen := d.Remotes[remote]; seen || len(d.Remotes) < maxRemotes {
		d.Remotes[remote] += size
	}
	if outbound {
		d.Up += size
		d.PktUp++
		b.Up += size
		hb.Up += size
		ps.Up += size
		d.rateUp += size
	} else {
		d.Down += size
		d.PktDn++
		b.Down += size
		hb.Down += size
		ps.Down += size
		d.rateDown += size
	}
}

// handshake times TCP connection setup as the tunnel sees it: the gap between a device's SYN and the
// remote's SYN-ACK is the round trip from the device to that host. A retransmitted SYN is not timed.
func (d *device) handshake(now time.Time, remote [4]byte, rport, lport uint16, outbound bool, flags int, b *bucket) {
	const syn, ack = 0x02, 0x10
	k := synKey{remote, rport, lport}
	switch {
	case outbound && flags&(syn|ack) == syn:
		if d.syns == nil {
			d.syns = map[synKey]synState{}
		}
		if st, ok := d.syns[k]; ok {
			st.Retx = true
			d.syns[k] = st
			return
		}
		if len(d.syns) >= maxSyns {
			for old, st := range d.syns {
				if now.Sub(st.At) > synTimeout {
					delete(d.syns, old)
				}
			}
			if len(d.syns) >= maxSyns {
				return
			}
		}
		d.syns[k] = synState{At: now}
	case !outbound && flags&(syn|ack) == syn|ack:
		st, ok := d.syns[k]
		if !ok {
			return
		}
		delete(d.syns, k)
		rtt := now.Sub(st.At)
		if st.Retx || rtt <= 0 || rtt > synTimeout {
			return
		}
		minute := now.Unix() / 60
		if d.rttMinute != minute {
			d.rttMinute, d.rttSamples = minute, d.rttSamples[:0]
		}
		if len(d.rttSamples) < maxRTTSamples {
			d.rttSamples = append(d.rttSamples, uint32(rtt/(100*time.Microsecond))+1)
		}
		sorted := append([]uint32(nil), d.rttSamples...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		b.RTT = sorted[len(sorted)/2]
		d.lastRTT, d.lastRTTAt = b.RTT, now
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
	byCategory := map[string]*categoryRow{}
	for k, v := range d.Ports {
		name := Category(k.Proto, k.Port)
		c := byCategory[name]
		if c == nil {
			c = &categoryRow{Category: name}
			byCategory[name] = c
		}
		c.Up, c.Down = c.Up+v.Up, c.Down+v.Down
	}
	categories := make([]*categoryRow, 0, len(byCategory))
	for _, c := range byCategory {
		categories = append(categories, c)
	}
	sort.Slice(categories, func(i, j int) bool { return categories[i].Up+categories[i].Down > categories[j].Up+categories[j].Down })
	// One [unix seconds, tenths of a ms] pair per minute that timed at least one TCP handshake.
	latency := make([][2]uint64, 0)
	for _, b := range d.History {
		if b.RTT > 0 {
			latency = append(latency, [2]uint64{uint64(b.Minute * 60), uint64(b.RTT)})
		}
	}
	// Rolling windows and a per-day breakdown from the hourly totals (day 0 is the last 24 hours).
	nowHour := now.Unix() / 3600
	window := func(hours int64) map[string]uint64 {
		w := map[string]uint64{}
		for _, h := range d.Hours {
			if h.Hour > nowHour-hours {
				w["up"], w["down"] = w["up"]+h.Up, w["down"]+h.Down
			}
		}
		return w
	}
	daily := make([][2]uint64, 30)
	for _, h := range d.Hours {
		if age := nowHour - h.Hour; age >= 0 && age < 30*24 {
			day := age / 24
			daily[day][0], daily[day][1] = daily[day][0]+h.Up, daily[day][1]+h.Down
		}
	}
	rttMS := 0.0
	if d.lastRTT > 0 && now.Sub(d.lastRTTAt) <= 2*time.Minute {
		rttMS = float64(d.lastRTT) / 10
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
		"usage_day": window(24), "usage_week": window(7 * 24), "usage_month": window(30 * 24), "usage_daily": daily, "rtt_ms": rttMS, "latency": latency, "categories": categories, "ports": ports, "active_ports": active, "services": services, "remotes": remotes, "history": history,
	}
}

type saved struct {
	Version int                    `json:"version"`
	Devices map[string]savedDevice `json:"devices"`
}

type savedDevice struct {
	Hours   []hourBucket `json:"hours,omitempty"`
	First   int64        `json:"first"`
	Up      uint64       `json:"up"`
	Down    uint64       `json:"down"`
	History []bucket     `json:"history"`
}

// Save writes totals and history (not the port breakdown, which is per session) to path.
func (t *Tracker) Save(path string) error {
	t.mu.Lock()
	s := saved{Version: 1, Devices: map[string]savedDevice{}}
	for ip, d := range t.devs {
		s.Devices[ipString(ip)] = savedDevice{First: d.First.Unix(), Up: d.Up, Down: d.Down, History: append([]bucket(nil), d.History...), Hours: append([]hourBucket(nil), d.Hours...)}
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
		hourCutoff := now.Unix()/3600 - historyHours
		for _, h := range sd.Hours {
			if h.Hour > hourCutoff {
				d.Hours = append(d.Hours, h)
			}
		}
		if len(d.Hours) == 0 { // a file from before hourly totals: the minutes it has give the first day
			for _, b := range d.History {
				hour := b.Minute / 60
				if n := len(d.Hours); n == 0 || d.Hours[n-1].Hour != hour {
					d.Hours = append(d.Hours, hourBucket{Hour: hour})
				}
				d.Hours[len(d.Hours)-1].Up += b.Up
				d.Hours[len(d.Hours)-1].Down += b.Down
			}
		}
		t.devs[ip] = d
	}
}
