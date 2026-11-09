package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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
	dnsFn    func([]byte) []byte
	open     func(lan.DeviceConfig) (lan.FrameIO, error)
	outbound func([]byte) bool
	out      func(map[string]any)
	now      func() time.Time

	mu      sync.Mutex
	gws     map[string]*runningGateway
	byIP    map[[4]byte]*lan.Gateway
	errs    map[string]string
	retryAt map[string]time.Time
	delvd   uint64
}

type runningGateway struct {
	gw     *lan.Gateway
	io     lan.FrameIO
	cancel context.CancelFunc
	mu     sync.Mutex
	err    error
	done   bool
	mac    string
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
	return &lanManager{devices: devices, client: client, mtu: mtu, open: openFrameIO, now: time.Now,
		gws: map[string]*runningGateway{}, byIP: map[[4]byte]*lan.Gateway{}, errs: map[string]string{}, retryAt: map[string]time.Time{},
		out: func(map[string]any) {}}, nil
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
		if rg != nil && rg.alive() {
			continue
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
	gw, err := lan.NewGateway(lan.Config{Device: dev, ClientIP: m.client, TunnelMTU: m.mtu, OnPacket: func(p []byte) { m.outbound(p) },
		DNSOverride: m.dnsFn}, io)
	if err != nil {
		io.Close()
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	rg := &runningGateway{gw: gw, io: io, cancel: cancel, mac: fmtMAC(io.MAC())}
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
		row := map[string]any{"name": d.Name, "tunnel_ip": d.TunnelIP.String(), "adapter_mac": rg.mac, "leased": rg.gw.IsLeased(), "up": rg.alive(), "error": nil,
			"frames_in": c.FramesIn, "frames_out": c.FramesOut, "packets_to_tunnel": c.PacketsToTunnel, "packets_from_tunnel": c.PacketsFromTunnel,
			"dhcp_offers": c.DHCPOffers, "dhcp_acks": c.DHCPAcks, "dns_overridden": c.DNSOverridden}
		if mac, ok := rg.gw.DeviceMAC(); ok {
			row["device_mac"] = fmtMAC(mac)
		} else {
			row["device_mac"] = ""
		}
		rows = append(rows, row)
	}
	return rows
}

// dnsStatus is dns_status: only while an override is applied to a live device.
func (m *lanManager) dnsStatus() any {
	if m == nil || m.dnsFn == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n uint64
	live := false
	for _, rg := range m.gws {
		if rg.alive() {
			live = true
			n += rg.gw.Stats().DNSOverridden
		}
	}
	if !live {
		return nil
	}
	return map[string]any{"scope": "connected_devices", "overrides": n}
}

func (m *lanManager) close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rg := range m.gws {
		rg.cancel()
		rg.io.Close()
	}
}

var errNoFrameIO = errors.New("LAN frame I/O is not available on this platform in the Go client")
