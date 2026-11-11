package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/lan"
)

// lanManager is userspace.py's maintain_lan/lan_status/lan_by_ip: it starts a
// gateway per configured device adapter, restarts failed ones every 5 s, and
// sends tunnel packets addressed to a device out its adapter. An unplugged or
// unsupported adapter never stops the tunnel.
type lanManager struct {
	devices  []lan.DeviceConfig
	client   netip.Addr
	mtu      int
	open     func(lan.DeviceConfig) (lan.FrameIO, error)
	outbound func([]byte) bool
	direct   *directUDP // set by the client when a device has udp_direct
	out      func(map[string]any)
	now      func() time.Time

	mu      sync.Mutex
	gws     map[string]*runningGateway
	byIP    map[[4]byte]*lan.Gateway
	errs    map[string]string
	retryAt map[string]time.Time
	delvd   uint64
	gaps    gapMeter

	// leases is the DHCP lease table that survives restarts (nil: memory only).
	leases *lan.LeaseTable
}

// lanStallReopen is how long an adapter may deliver no frames before it is reopened.
const lanStallReopen = 30 * time.Second

type runningGateway struct {
	gw     *lan.Gateway
	io     lan.FrameIO
	cancel context.CancelFunc
	mu     sync.Mutex
	err    error
	done   bool
	mac    string

	lastIn   uint64
	lastMove time.Time
}

func (r *runningGateway) alive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.done
}

func newLanManager(raw json.RawMessage, client netip.Addr, uplinkIDs []string, uplinkIndices []int, mtu int) (*lanManager, error) {
	devices, err := lan.LoadDevices(raw, client, uplinkIDs, uplinkIndices)
	if err != nil {
		return nil, err
	}
	// Reject contradictory GUID/index selections before any packet-filter open.
	// Keep the shared parser's Python compatibility contract unchanged.
	for _, d := range devices {
		for _, index := range uplinkIndices {
			if d.InterfaceIndex != 0 && d.InterfaceIndex == index {
				return nil, fmt.Errorf("%s: adapter is already selected as a VPN uplink", d.Name)
			}
		}
	}
	if len(devices) == 0 {
		return nil, nil
	}
	if mtu == 0 {
		mtu = 1280
	}
	return &lanManager{devices: devices, client: client, mtu: mtu, open: newSharedAdapters(openFrameIO).Open, now: time.Now,
		gws: map[string]*runningGateway{}, byIP: map[[4]byte]*lan.Gateway{}, errs: map[string]string{}, retryAt: map[string]time.Time{},
		out: func(map[string]any) {}}, nil
}

// useLeaseTable opens the persistent DHCP lease table every gateway shares. Each
// gateway reads its own row at start and writes it on ACK, release and MAC change.
func (m *lanManager) useLeaseTable(path string) {
	if m != nil && path != "" {
		m.leases = lan.OpenLeaseTable(path)
	}
}

// deviceIPs are the tunnel addresses of the attached devices.
func (m *lanManager) deviceIPs() []netip.Addr {
	if m == nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, d.TunnelIP)
	}
	return out
}

func fmtMAC(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// maintain starts missing gateways and replaces dead ones.
func (m *lanManager) maintain(ctx context.Context) {
	for _, d := range m.devices {
		m.mu.Lock()
		rg := m.gws[d.Name]
		m.mu.Unlock()
		if rg != nil && rg.alive() && m.sharedAdapter(d) {
			continue // the shared reader recovers a stale adapter for everyone
		}
		if rg != nil && rg.alive() {
			// Another handle on the same adapter (ProxiFyre restarting on a
			// reconnect) can take the frames; the newest handle wins. When no
			// frame arrives for a while, reopen to take them back.
			in := rg.gw.Stats().FramesIn
			now := m.now()
			if in != rg.lastIn || rg.lastMove.IsZero() {
				rg.lastIn, rg.lastMove = in, now
				continue
			}
			if now.Sub(rg.lastMove) < lanStallReopen {
				continue
			}
			rg.mu.Lock()
			rg.err = errors.New("no frames received; reopening adapter")
			rg.done = true
			rg.mu.Unlock()
		}
		if rg != nil {
			rg.mu.Lock()
			msg := "Adapter stopped"
			if rg.err != nil {
				msg = rg.err.Error()
			}
			rg.mu.Unlock()
			m.mu.Lock()
			m.errs[d.Name] = msg
			if ip := d.TunnelIP.As4(); m.byIP[ip] == rg.gw {
				delete(m.byIP, ip)
			}
			delete(m.gws, d.Name)
			m.mu.Unlock()
			rg.cancel()
			rg.io.Close()
			m.out(map[string]any{"status": "lan_device_down", "name": d.Name, "error": msg})
		}
		now := m.now()
		m.mu.Lock()
		wait := now.Before(m.retryAt[d.Name])
		if !wait {
			m.retryAt[d.Name] = now.Add(5 * time.Second)
		}
		m.mu.Unlock()
		if wait {
			continue
		}
		rg, err := m.start(ctx, d)
		if err != nil {
			m.mu.Lock()
			changed := m.errs[d.Name] != err.Error()
			m.errs[d.Name] = err.Error()
			m.mu.Unlock()
			if changed {
				m.out(map[string]any{"status": "lan_device_unavailable", "name": d.Name, "error": err.Error()})
			}
			continue
		}
		m.mu.Lock()
		m.gws[d.Name] = rg
		m.byIP[d.TunnelIP.As4()] = rg.gw
		delete(m.errs, d.Name)
		m.mu.Unlock()
		m.out(map[string]any{"status": "lan_device_up", "name": d.Name, "tunnel_ip": d.TunnelIP.String(), "adapter_mac": rg.mac})
	}
}

func (m *lanManager) start(ctx context.Context, d lan.DeviceConfig) (*runningGateway, error) {
	io, err := m.open(d)
	if err != nil {
		return nil, err
	}
	dev := lan.Device{Name: d.Name, TunnelIP: d.TunnelIP, DNS: d.DNS}
	if d.DeviceMAC != "" {
		mac, err := lan.ParseMAC(d.DeviceMAC)
		if err != nil {
			io.Close()
			return nil, err
		}
		dev.PinnedMAC = &mac
	}
	gw, err := lan.NewGateway(lan.Config{Device: dev, Leases: m.leases, ClientIP: m.client, TunnelMTU: m.mtu, OnPacket: func(p []byte) {
		if d.UDPDirect && m.direct != nil && m.direct.Handle(p) {
			return
		}
		m.outbound(p)
	}}, io)
	if err != nil {
		io.Close()
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	rg := &runningGateway{gw: gw, io: io, cancel: cancel, mac: fmtMAC(io.MAC())}
	gw.Announce()
	go func() { // time the adapter-to-device leg: ten echoes a second
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
				gw.ProbeDevice()
			}
		}
	}()
	go func() {
		err := gw.Run(cctx, io)
		rg.mu.Lock()
		rg.err, rg.done = err, true
		rg.mu.Unlock()
	}()
	return rg, nil
}

// dispatch sends a tunnel packet addressed to an attached device out its
// adapter. handled is true when a gateway owns the destination address (the
// packet never enters the local netstack, delivered or not).
func (m *lanManager) dispatch(packet []byte) (handled bool) {
	if m == nil || len(packet) < 20 {
		return false
	}
	var dst [4]byte
	copy(dst[:], packet[16:20])
	m.mu.Lock()
	gw := m.byIP[dst]
	m.mu.Unlock()
	if gw == nil {
		return false
	}
	if gw.Deliver(packet) {
		m.mu.Lock()
		m.delvd++
		m.gaps.observe(packet, m.now())
		m.mu.Unlock()
	}
	return true
}

// status is lan_devices for the status file.
func (m *lanManager) status() any {
	if m == nil {
		return []any{}
	}
	rows := make([]map[string]any, 0, len(m.devices))
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.devices {
		rg := m.gws[d.Name]
		if rg == nil {
			e := m.errs[d.Name]
			if e == "" {
				e = "Starting"
			}
			rows = append(rows, map[string]any{"name": d.Name, "tunnel_ip": d.TunnelIP.String(), "up": false, "leased": false, "error": e})
			continue
		}
		c := rg.gw.Stats()
		row := map[string]any{"name": d.Name, "tunnel_ip": d.TunnelIP.String(), "adapter_mac": rg.mac, "leased": rg.gw.IsLeased(), "present": rg.gw.Present(), "silent_s": rg.gw.SilentFor().Seconds(), "up": rg.alive(), "error": nil,
			"frames_in": c.FramesIn, "frames_out": c.FramesOut, "packets_to_tunnel": c.PacketsToTunnel, "packets_from_tunnel": c.PacketsFromTunnel, "bytes_to_tunnel": c.BytesToTunnel, "bytes_from_tunnel": c.BytesFromTunnel,
			"dhcp_offers": c.DHCPOffers, "dhcp_acks": c.DHCPAcks,
			"udp_direct": m.directStatus(d), "oversize_fragmented": c.Fragmented, "oversize_df_dropped": c.FragNeededSent, "tunnel_to_device_malformed": c.Malformed}
		if mac, ok := rg.gw.DeviceMAC(); ok {
			row["device_mac"] = fmtMAC(mac)
		} else {
			row["device_mac"] = ""
		}
		if l, ok := rg.gw.Lease(); ok {
			lease := map[string]any{"mac": l.MAC, "ip": l.IP, "leased": rg.gw.IsLeased(), "granted": l.Granted}
			if l.Expires > 0 {
				lease["expires_in_s"] = l.Expires - m.now().Unix()
			}
			row["lease"] = lease
		}
		row["downstream_gaps"] = m.gaps.report()
		row["device_probe"] = rg.gw.ProbeStats()
		rows = append(rows, row)
	}
	return rows
}

func (m *lanManager) close() {
	if m == nil {
		return
	}
	m.direct.close()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rg := range m.gws {
		rg.cancel()
		rg.io.Close()
	}
}

// directStatus is the passthrough counters of a udp_direct device (nil otherwise).
func (m *lanManager) directStatus(d lan.DeviceConfig) any {
	if !d.UDPDirect || m.direct == nil {
		return nil
	}
	return m.direct.stats()
}

var errNoFrameIO = errors.New("LAN frame I/O is not available on this platform in the Go client")

// gapMeter measures how evenly each downstream UDP flow reaches the device:
// the gap between consecutive packets of one flow, bucketed. Flows idle for
// over two seconds restart rather than count as a gap. Callers hold the lock.
type gapMeter struct {
	last                       map[[10]byte]time.Time
	n, over40, over60, over100 uint64
	maxMS                      float64
	sumMS                      float64
	// By packet size (IP length): the priority class stops at 420 bytes, so
	// larger game packets travel as ordinary striped traffic.
	smallN, smallOver40, bigN, bigOver40 uint64
	smallMax, bigMax                     float64
	sizeBuckets                          [5]uint64 // <=200, <=420, <=800, <=1200, larger
}

func (g *gapMeter) observe(p []byte, now time.Time) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
		return
	}
	ihl := int(p[0]&15) * 4
	if len(p) < ihl+4 {
		return
	}
	size := int(p[2])<<8 | int(p[3])
	if sp, dp := int(p[ihl])<<8|int(p[ihl+1]), int(p[ihl+2])<<8|int(p[ihl+3]); sp == 53 || dp == 53 || sp == 443 || dp == 443 {
		return
	}
	switch {
	case size <= 200:
		g.sizeBuckets[0]++
	case size <= 420:
		g.sizeBuckets[1]++
	case size <= 800:
		g.sizeBuckets[2]++
	case size <= 1200:
		g.sizeBuckets[3]++
	default:
		g.sizeBuckets[4]++
	}
	var k [10]byte
	copy(k[0:4], p[12:16])
	copy(k[4:6], p[ihl:ihl+2])
	copy(k[6:10], p[ihl+2:ihl+4])
	if g.last == nil {
		g.last = map[[10]byte]time.Time{}
	}
	prev, ok := g.last[k]
	g.last[k] = now
	if len(g.last) > 256 {
		g.last = map[[10]byte]time.Time{k: now}
	}
	if !ok || now.Sub(prev) > 2*time.Second {
		return
	}
	ms := float64(now.Sub(prev)) / float64(time.Millisecond)
	g.n++
	g.sumMS += ms
	if ms > g.maxMS {
		g.maxMS = ms
	}
	if size > 420 {
		g.bigN++
		g.bigMax = max(g.bigMax, ms)
		if ms > 40 {
			g.bigOver40++
		}
	} else {
		g.smallN++
		g.smallMax = max(g.smallMax, ms)
		if ms > 40 {
			g.smallOver40++
		}
	}
	if ms > 40 {
		g.over40++
	}
	if ms > 60 {
		g.over60++
	}
	if ms > 100 {
		g.over100++
	}
}

func (g *gapMeter) report() map[string]any {
	mean := 0.0
	if g.n > 0 {
		mean = g.sumMS / float64(g.n)
	}
	return map[string]any{"small_le420": map[string]any{"samples": g.smallN, "over_40ms": g.smallOver40, "max_ms": g.smallMax},
		"big_gt420":                            map[string]any{"samples": g.bigN, "over_40ms": g.bigOver40, "max_ms": g.bigMax},
		"size_buckets_le200_420_800_1200_more": g.sizeBuckets, "samples": g.n, "mean_ms": mean, "max_ms": g.maxMS, "over_40ms": g.over40, "over_60ms": g.over60, "over_100ms": g.over100}
}

// sharedAdapter reports whether another configured device uses d's adapter.
func (m *lanManager) sharedAdapter(d lan.DeviceConfig) bool {
	n := 0
	for _, o := range m.devices {
		if strings.EqualFold(o.InterfaceID, d.InterfaceID) && o.InterfaceID != "" {
			n++
		}
	}
	return n > 1
}
