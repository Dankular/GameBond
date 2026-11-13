package lan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	ethVLAN            = 0x8100
	maxLocalNeighbors  = 4096
	maxPendingPerPeer  = 16
	maxPendingLocalAll = 512
	pendingNeighborTTL = 30 * time.Second
)

// FramePort binds one normalized local network to its raw Ethernet adapter.
// VLANVerified must be true for tagged networks; false fails closed.
type FramePort struct {
	Network      NetworkConfig
	IO           FrameIO
	VLANVerified bool
}

// LocalRouterStats contains forwarding and drop counters.
type LocalRouterStats struct {
	FramesIn, FramesOut, PacketsRouted, PacketsToTunnel, PacketsFromTunnel uint64
	ARPReplies, NeighborLearned, NeighborMisses, QueueDrops                uint64
	SpoofedSourceDropped, InterNetworkDenied, TTLExpired, Malformed        uint64
	NoRoute, WriteErrors, OversizeDropped, VLANRejected                    uint64
}

type localPort struct {
	network NetworkConfig
	io      FrameIO
	mac     [6]byte
	dhcp    *DHCPServer
	relay   *DHCPRelay
}

type localNeighbor struct {
	mac  [6]byte
	seen time.Time
	port string
}

type pendingPacket struct {
	packet  []byte
	expires time.Time
}

type neighborKey struct {
	port string
	ip   netip.Addr
}

// LocalRouter serves DHCP, ARP, and IPv4 routing for configured local networks.
// It never changes the host's operating-system routing table.
type LocalRouter struct {
	mu        sync.Mutex
	config    LocalConfig
	routes    *RouteTable
	ports     map[string]*localPort
	byName    map[string]*localPort
	neighbors map[neighborKey]localNeighbor
	pending   map[neighborKey][]pendingPacket
	pendingN  int
	poolLease *PoolLeaseTable
	outbound  func([]byte) bool
	now       func() time.Time
	mtu       int
	tunnelMTU int
	stats     LocalRouterStats
}

// NewLocalRouter constructs a router over already-open configured ports.
func NewLocalRouter(config LocalConfig, ports []FramePort, leases *PoolLeaseTable, outbound func([]byte) bool, now func() time.Time) (*LocalRouter, error) {
	if len(config.Networks) == 0 || len(ports) != len(config.Networks) {
		return nil, errors.New("local router requires one frame port per configured network")
	}
	if now == nil {
		now = time.Now
	}
	if outbound == nil {
		outbound = func([]byte) bool { return false }
	}
	r := &LocalRouter{config: config, routes: NewRouteTable(config), ports: map[string]*localPort{}, byName: map[string]*localPort{}, neighbors: map[neighborKey]localNeighbor{}, pending: map[neighborKey][]pendingPacket{}, poolLease: leases, outbound: outbound, now: now, mtu: DeviceMTU, tunnelMTU: DefaultTunnelM}
	for _, framePort := range ports {
		n := framePort.Network
		if n.Name == "" || !n.Prefix.IsValid() {
			return nil, errors.New("local router has an invalid frame port")
		}
		if n.VLANID != 0 && !framePort.VLANVerified {
			return nil, fmt.Errorf("VLAN %d on %q is unavailable because tagged frame support is unverified", n.VLANID, n.Name)
		}
		identity := networkIdentity(n)
		key := localPortKey(identity, n.VLANID)
		if r.ports[key] != nil || r.byName[strings.ToLower(n.Name)] != nil {
			return nil, fmt.Errorf("duplicate local router port %q", n.Name)
		}
		port := &localPort{network: n, io: framePort.IO}
		r.ports[key] = port
		r.byName[strings.ToLower(n.Name)] = port
		if framePort.IO != nil {
			if err := r.attachPort(port, framePort.IO); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

// SetPort replaces or removes one network's adapter without rebuilding other
// routes or interfaces. It is safe while frame readers are active.
func (r *LocalRouter) SetPort(name string, io FrameIO) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	port := r.byName[strings.ToLower(name)]
	if port == nil {
		return fmt.Errorf("unknown local network %q", name)
	}
	port.dhcp, port.relay = nil, nil
	port.io = io
	port.mac = [6]byte{}
	for key := range r.neighbors {
		if key.port == strings.ToLower(port.network.Name) {
			delete(r.neighbors, key)
		}
	}
	for key, queue := range r.pending {
		if key.port == strings.ToLower(port.network.Name) {
			r.pendingN -= len(queue)
			delete(r.pending, key)
		}
	}
	if io == nil {
		return nil
	}
	return r.attachPort(port, io)
}

// SetOutbound replaces the callback used for destinations without a configured
// local route; the callback normally submits the IPv4 packet to GameBond.
func (r *LocalRouter) SetOutbound(outbound func([]byte) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if outbound == nil {
		r.outbound = func([]byte) bool { return false }
		return
	}
	r.outbound = outbound
}

// SetTunnelMTU sets the maximum IPv4 packet size submitted to the tunnel.
func (r *LocalRouter) SetTunnelMTU(mtu int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mtu >= 576 && mtu <= 65535 {
		r.tunnelMTU = mtu
	}
}

func (r *LocalRouter) attachPort(port *localPort, io FrameIO) error {
	port.io, port.mac = io, io.MAC()
	if port.network.DHCP != nil {
		server, err := NewDHCPServer(port.network, port.mac, r.poolLease, r.now)
		if err != nil {
			return err
		}
		port.dhcp = server
	}
	if port.network.Relay != nil {
		relay, err := NewDHCPRelay(port.network, port.mac, r.now)
		if err != nil {
			return err
		}
		port.relay = relay
	}
	return nil
}

func localPortKey(identity string, vlan int) string {
	return strings.ToLower(identity) + "|" + fmt.Sprint(vlan)
}

type ethernetFrame struct {
	dst, src  [6]byte
	ethertype uint16
	vlan      int
	payload   []byte
}

func parseEthernet(frame []byte) (ethernetFrame, bool) {
	var out ethernetFrame
	if len(frame) < 14 {
		return out, false
	}
	copy(out.dst[:], frame[:6])
	copy(out.src[:], frame[6:12])
	out.ethertype = binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	if out.ethertype == ethVLAN {
		if len(frame) < 18 {
			return out, false
		}
		tci := binary.BigEndian.Uint16(frame[14:16])
		out.vlan = int(tci & 0x0fff)
		out.ethertype = binary.BigEndian.Uint16(frame[16:18])
		offset = 18
	}
	out.payload = frame[offset:]
	return out, true
}

func encodeEthernet(dst, src [6]byte, ethertype uint16, payload []byte, vlan int) []byte {
	frame := make([]byte, 14, 14+len(payload))
	copy(frame[:6], dst[:])
	copy(frame[6:12], src[:])
	if vlan > 0 {
		frame = append(frame[:12], byte(ethVLAN>>8), byte(ethVLAN&0xff), byte(vlan>>8), byte(vlan))
		frame = binary.BigEndian.AppendUint16(frame, ethertype)
	} else {
		binary.BigEndian.PutUint16(frame[12:14], ethertype)
	}
	return append(frame, payload...)
}

// HandleFrame processes one frame on the named adapter. interfaceID must be
// the stable configured adapter identity, not a value taken from the packet.
func (r *LocalRouter) HandleFrame(interfaceID string, frame []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expirePending()
	r.stats.FramesIn++
	f, ok := parseEthernet(frame)
	if !ok {
		r.stats.Malformed++
		return
	}
	port := r.ports[localPortKey(interfaceID, f.vlan)]
	if port == nil || (f.vlan != 0 && port.network.VLANID != f.vlan) {
		r.stats.VLANRejected++
		return
	}
	if f.src == port.mac || (f.dst != port.mac && f.dst != broadcastMAC) {
		return
	}
	plain := encodeEthernet(f.dst, f.src, f.ethertype, f.payload, 0)
	if port.relay != nil {
		requests, handled := port.relay.HandleClient(plain)
		if handled {
			for _, request := range requests {
				route, ok := r.routes.Lookup(request.Server)
				if !ok {
					r.stats.NoRoute++
					continue
				}
				egress := r.byName[strings.ToLower(route.Network.Name)]
				if egress == nil {
					r.stats.NoRoute++
					continue
				}
				r.sendToNextHop(egress, route.NextHop, request.Packet)
			}
			return
		}
	}
	if port.dhcp != nil {
		if reply, handled := port.dhcp.Handle(plain); handled {
			if len(reply) != 0 {
				if f.vlan != 0 {
					reply = tagFrame(reply, f.vlan)
				}
				r.write(port, reply)
			}
			return
		}
	}
	switch f.ethertype {
	case ethARP:
		r.handleARP(port, f)
	case ethIPv4:
		r.handleIPv4(port, f)
	}
}

func tagFrame(frame []byte, vlan int) []byte {
	f, ok := parseEthernet(frame)
	if !ok || f.vlan != 0 {
		return frame
	}
	return encodeEthernet(f.dst, f.src, f.ethertype, f.payload, vlan)
}

func (r *LocalRouter) handleARP(port *localPort, frame ethernetFrame) {
	b := frame.payload
	if len(b) < 28 || !bytesEqual(b[:6], []byte{0, 1, 8, 0, 6, 4}) {
		r.stats.Malformed++
		return
	}
	op := binary.BigEndian.Uint16(b[6:8])
	var senderMAC [6]byte
	var senderIP, targetIP [4]byte
	copy(senderMAC[:], b[8:14])
	copy(senderIP[:], b[14:18])
	copy(targetIP[:], b[24:28])
	if senderMAC != frame.src || senderMAC == ([6]byte{}) || senderMAC[0]&1 != 0 || (op != 1 && op != 2) {
		r.stats.Malformed++
		return
	}
	if senderIP != [4]byte{} {
		source := netip.AddrFrom4(senderIP)
		if !usableHost(port.network.Prefix, source) || source == port.network.Prefix.Addr() {
			r.stats.SpoofedSourceDropped++
			return
		}
		r.learn(port, source, senderMAC)
	}
	if op == 1 && targetIP == port.network.Prefix.Addr().As4() {
		gateway := port.network.Prefix.Addr().As4()
		reply := []byte{0, 1, 8, 0, 6, 4, 0, 2}
		reply = append(reply, port.mac[:]...)
		reply = append(reply, gateway[:]...)
		reply = append(reply, frame.src[:]...)
		reply = append(reply, senderIP[:]...)
		r.write(port, encodeEthernet(frame.src, port.mac, ethARP, reply, port.network.VLANID))
		r.stats.ARPReplies++
	}
}

func (r *LocalRouter) handleIPv4(port *localPort, frame ethernetFrame) {
	header, protocol, src, dst, total, ok := parseIPv4(frame.payload)
	if !ok {
		r.stats.Malformed++
		return
	}
	packet := append([]byte(nil), frame.payload[:total]...)
	source, destination := netip.AddrFrom4(src), netip.AddrFrom4(dst)
	if protocol == 17 && total >= header+8 && binary.BigEndian.Uint16(packet[header:header+2]) == 67 && binary.BigEndian.Uint16(packet[header+2:header+4]) == 67 {
		if r.handleRelayReply(port, source, packet) {
			return
		}
	}
	if !r.validIngressSource(port, source) {
		r.stats.SpoofedSourceDropped++
		return
	}
	r.learn(port, source, frame.src)
	if destination.IsMulticast() || destination.IsUnspecified() || destination.IsLoopback() || destination == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		r.stats.NoRoute++
		return
	}
	r.forwardIngress(port, packet, destination)
}

func (r *LocalRouter) validIngressSource(port *localPort, source netip.Addr) bool {
	if !isUnicastAddress(source) || source == port.network.Prefix.Addr() {
		return false
	}
	route, ok := r.routes.Lookup(source)
	return ok && strings.EqualFold(route.Network.Name, port.network.Name)
}

func (r *LocalRouter) handleRelayReply(ingress *localPort, server netip.Addr, packet []byte) bool {
	route, ok := r.routes.Lookup(server)
	if !ok || !strings.EqualFold(route.Network.Name, ingress.network.Name) {
		return false
	}
	for _, port := range r.byName {
		if port.relay == nil {
			continue
		}
		configured := false
		for _, candidate := range port.network.Relay.Servers {
			if candidate == server {
				configured = true
				break
			}
		}
		if !configured {
			continue
		}
		frame, handled := port.relay.HandleServer(server, packet)
		if handled {
			r.write(port, frame)
			return true
		}
	}
	return false
}

func (r *LocalRouter) forwardIngress(ingress *localPort, packet []byte, destination netip.Addr) {
	route, found := r.routes.Lookup(destination)
	if !found {
		forwarded := decrementTTL(packet)
		if forwarded == nil {
			r.stats.TTLExpired++
			return
		}
		forwarded = clampTCPMSS(forwarded, r.tunnelMTU-40)
		pieces := [][]byte{forwarded}
		if len(forwarded) > r.tunnelMTU {
			if binary.BigEndian.Uint16(forwarded[6:8])&0x4000 != 0 {
				r.stats.OversizeDropped++
				return
			}
			pieces = fragmentIPv4(forwarded, r.tunnelMTU)
			if len(pieces) == 0 {
				r.stats.OversizeDropped++
				return
			}
		}
		for _, piece := range pieces {
			if !r.outbound(piece) {
				r.stats.NoRoute++
				return
			}
			r.stats.PacketsToTunnel++
		}
		return
	}
	egress := r.byName[strings.ToLower(route.Network.Name)]
	if egress == nil {
		r.stats.NoRoute++
		return
	}
	if ingress != nil && ingress != egress && !allowsForward(ingress.network, egress.network.Name) {
		r.stats.InterNetworkDenied++
		return
	}
	forwarded := decrementTTL(packet)
	if forwarded == nil {
		r.stats.TTLExpired++
		return
	}
	forwarded = clampTCPMSS(forwarded, r.mtu-40)
	if len(forwarded) > r.mtu {
		if binary.BigEndian.Uint16(forwarded[6:8])&0x4000 != 0 {
			r.stats.OversizeDropped++
			return
		}
		pieces := fragmentIPv4(forwarded, r.mtu)
		if len(pieces) == 0 {
			r.stats.OversizeDropped++
			return
		}
		for _, piece := range pieces {
			r.sendToNextHop(egress, route.NextHop, piece)
		}
	} else {
		r.sendToNextHop(egress, route.NextHop, forwarded)
	}
	r.stats.PacketsRouted++
}

func allowsForward(source NetworkConfig, destination string) bool {
	for _, allowed := range source.ForwardTo {
		if strings.EqualFold(allowed, destination) {
			return true
		}
	}
	return false
}

func (r *LocalRouter) sendToNextHop(port *localPort, nextHop netip.Addr, packet []byte) {
	key := neighborKey{port: strings.ToLower(port.network.Name), ip: nextHop}
	if neighbor, ok := r.neighbors[key]; ok && r.now().Sub(neighbor.seen) < 2*time.Minute {
		r.write(port, encodeEthernet(neighbor.mac, port.mac, ethIPv4, packet, port.network.VLANID))
		return
	}
	r.stats.NeighborMisses++
	queue := r.pending[key]
	if len(queue) >= maxPendingPerPeer || r.pendingN >= maxPendingLocalAll {
		r.stats.QueueDrops++
		return
	}
	if len(queue) == 0 {
		r.sendARPRequest(port, nextHop)
	}
	r.pending[key] = append(queue, pendingPacket{packet: append([]byte(nil), packet...), expires: r.now().Add(pendingNeighborTTL)})
	r.pendingN++
}

func (r *LocalRouter) sendARPRequest(port *localPort, target netip.Addr) {
	sender := port.network.Prefix.Addr().As4()
	targetBytes := target.As4()
	body := []byte{0, 1, 8, 0, 6, 4, 0, 1}
	body = append(body, port.mac[:]...)
	body = append(body, sender[:]...)
	body = append(body, make([]byte, 6)...)
	body = append(body, targetBytes[:]...)
	r.write(port, encodeEthernet(broadcastMAC, port.mac, ethARP, body, port.network.VLANID))
}

func (r *LocalRouter) learn(port *localPort, ip netip.Addr, mac [6]byte) {
	key := neighborKey{port: strings.ToLower(port.network.Name), ip: ip}
	if _, exists := r.neighbors[key]; !exists && len(r.neighbors) >= maxLocalNeighbors {
		var oldest neighborKey
		var at time.Time
		for candidate, entry := range r.neighbors {
			if at.IsZero() || entry.seen.Before(at) {
				oldest, at = candidate, entry.seen
			}
		}
		delete(r.neighbors, oldest)
	}
	r.neighbors[key] = localNeighbor{mac: mac, seen: r.now(), port: key.port}
	r.stats.NeighborLearned++
	queued := r.pending[key]
	delete(r.pending, key)
	r.pendingN -= len(queued)
	for _, item := range queued {
		if r.now().Before(item.expires) {
			r.write(port, encodeEthernet(mac, port.mac, ethIPv4, item.packet, port.network.VLANID))
		} else {
			r.stats.QueueDrops++
		}
	}
}

func (r *LocalRouter) expirePending() {
	now := r.now()
	for key, queue := range r.pending {
		kept := queue[:0]
		for _, item := range queue {
			if now.Before(item.expires) {
				kept = append(kept, item)
			} else {
				r.pendingN--
				r.stats.QueueDrops++
			}
		}
		if len(kept) == 0 {
			delete(r.pending, key)
		} else {
			r.pending[key] = kept
		}
	}
}

// ForwardFromTunnel sends a packet to a configured connected/static route.
// It returns true when a local route owns the destination, even if delivery fails.
func (r *LocalRouter) ForwardFromTunnel(packet []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expirePending()
	if len(packet) < 20 {
		return false
	}
	dst := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	route, ok := r.routes.Lookup(dst)
	if !ok {
		return false
	}
	forwarded := decrementTTL(packet)
	if forwarded == nil {
		r.stats.TTLExpired++
		return true
	}
	port := r.byName[strings.ToLower(route.Network.Name)]
	if port == nil {
		r.stats.NoRoute++
		return true
	}
	forwarded = clampTCPMSS(forwarded, r.mtu-40)
	if len(forwarded) > r.mtu {
		if binary.BigEndian.Uint16(forwarded[6:8])&0x4000 != 0 {
			r.stats.OversizeDropped++
			return true
		}
		pieces := fragmentIPv4(forwarded, r.mtu)
		if len(pieces) == 0 {
			r.stats.OversizeDropped++
			return true
		}
		for _, piece := range pieces {
			r.sendToNextHop(port, route.NextHop, piece)
		}
	} else {
		r.sendToNextHop(port, route.NextHop, forwarded)
	}
	r.stats.PacketsFromTunnel++
	return true
}

// Status returns a stable status snapshot for configured local networks.
func (r *LocalRouter) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	rows := make([]map[string]any, 0, len(r.config.Networks))
	for _, network := range r.config.Networks {
		port := r.byName[strings.ToLower(network.Name)]
		neighbors := 0
		for key := range r.neighbors {
			if key.port == strings.ToLower(network.Name) {
				neighbors++
			}
		}
		row := map[string]any{"name": network.Name, "prefix": network.Prefix.String(), "vlan_id": network.VLANID, "up": port != nil && port.io != nil, "neighbors": neighbors, "dhcp": network.DHCP != nil, "relay": network.Relay != nil}
		if network.DHCP != nil {
			poolSize := int(ipv4Number(network.DHCP.End) - ipv4Number(network.DHCP.Start) + 1)
			leased := 0
			if r.poolLease != nil {
				for _, lease := range r.poolLease.Rows() {
					if lease.Network == network.Name && r.now().Before(lease.Expires) {
						leased++
					}
				}
			}
			free := poolSize - leased
			if free < 0 {
				free = 0
			}
			row["dhcp_pool"] = map[string]any{"start": network.DHCP.Start.String(), "end": network.DHCP.End.String(), "size": poolSize, "leased": leased, "free": free, "lease_seconds": network.DHCP.LeaseSeconds}
		}
		if port != nil && port.dhcp != nil {
			stats := port.dhcp.Stats()
			row["dhcp_stats"] = stats
		}
		if port != nil && port.relay != nil {
			row["relay_stats"] = port.relay.Stats()
		}
		rows = append(rows, row)
	}
	return map[string]any{"networks": rows, "routes": r.routes.Routes(), "stats": r.stats}
}

func (r *LocalRouter) write(port *localPort, frame []byte) {
	if port.io == nil {
		r.stats.WriteErrors++
		return
	}
	if err := port.io.Write(frame); err != nil {
		r.stats.WriteErrors++
		return
	}
	r.stats.FramesOut++
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
