package lan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const (
	maxRelayTransactions = 1024
	relayTransactionTTL  = 30 * time.Second
)

// RelayPacket is one DHCP datagram to send toward a configured relay server.
type RelayPacket struct {
	Server netip.Addr
	Packet []byte
}

type relayKey struct {
	xid [4]byte
	mac [6]byte
}

type relayTransaction struct {
	created time.Time
}

// DHCPRelayStats reports relay activity and rejected responses.
type DHCPRelayStats struct {
	Requests, Replies, Rejected, Expired uint64
}

// DHCPRelay relays client requests from one local network to explicitly
// configured DHCP servers and maps valid replies back to that network.
type DHCPRelay struct {
	mu      sync.Mutex
	network NetworkConfig
	mac     [6]byte
	now     func() time.Time
	pending map[relayKey]relayTransaction
	stats   DHCPRelayStats
}

// NewDHCPRelay creates a relay for a network configured in relay mode.
func NewDHCPRelay(network NetworkConfig, mac [6]byte, now func() time.Time) (*DHCPRelay, error) {
	if network.Relay == nil || len(network.Relay.Servers) == 0 || !network.Prefix.IsValid() || !network.Prefix.Addr().Is4() || mac == ([6]byte{}) || mac[0]&1 != 0 {
		return nil, fmt.Errorf("network %q has invalid DHCP relay settings", network.Name)
	}
	if now == nil {
		now = time.Now
	}
	return &DHCPRelay{network: network, mac: mac, now: now, pending: map[relayKey]relayTransaction{}}, nil
}

// HandleClient transforms a client DHCP request into one unicast datagram per
// configured server. Requests with a pre-existing relay address are rejected.
func (r *DHCPRelay) HandleClient(frame []byte) ([]RelayPacket, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := parseEthernet(frame)
	if !ok || f.ethertype != ethIPv4 {
		return nil, false
	}
	header, proto, src, dst, total, ok := parseIPv4(f.payload)
	if !ok || proto != 17 || total < header+8 {
		return nil, false
	}
	udp := f.payload[header:total]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if binary.BigEndian.Uint16(udp[:2]) != 68 || binary.BigEndian.Uint16(udp[2:4]) != 67 || udpLen < 8 || udpLen > len(udp) {
		return nil, false
	}
	request := udp[8:udpLen]
	if len(request) < 240 || request[0] != 1 || request[1] != 1 || request[2] != 6 || !bytes.Equal(request[236:240], []byte{0x63, 0x82, 0x53, 0x63}) {
		r.stats.Rejected++
		return nil, true
	}
	var clientMAC [6]byte
	copy(clientMAC[:], request[28:34])
	if clientMAC != f.src || clientMAC == ([6]byte{}) || clientMAC[0]&1 != 0 || !bytes.Equal(request[24:28], []byte{0, 0, 0, 0}) || request[3] >= 16 {
		r.stats.Rejected++
		return nil, true
	}
	source := netip.AddrFrom4(src)
	if source != netip.AddrFrom4([4]byte{}) && !r.network.Prefix.Contains(source) {
		r.stats.Rejected++
		return nil, true
	}
	destination := netip.AddrFrom4(dst)
	if destination != netip.AddrFrom4([4]byte{255, 255, 255, 255}) && destination != r.network.Prefix.Addr() {
		r.stats.Rejected++
		return nil, true
	}
	options, valid := parseDHCPOptions(request[240:])
	if !valid || len(options[53]) != 1 {
		r.stats.Rejected++
		return nil, true
	}
	switch options[53][0] {
	case 1, 3, 4, 7, 8:
	default:
		return nil, true
	}
	requestCopy := append([]byte(nil), request...)
	requestCopy[3]++
	copy(requestCopy[24:28], r.network.Prefix.Addr().AsSlice())
	var xid [4]byte
	copy(xid[:], requestCopy[4:8])
	now := r.now()
	r.expireLocked(now)
	key := relayKey{xid: xid, mac: clientMAC}
	kind := options[53][0]
	if kind == 1 || kind == 3 || kind == 4 || kind == 8 {
		if len(r.pending) >= maxRelayTransactions {
			r.stats.Rejected++
			return nil, true
		}
		r.pending[key] = relayTransaction{created: now}
	}
	clientIP := r.network.Prefix.Addr().As4()
	var out []RelayPacket
	for _, server := range r.network.Relay.Servers {
		dst := server.As4()
		udpPacket := buildUDP(clientIP, dst, 67, 67, requestCopy)
		out = append(out, RelayPacket{Server: server, Packet: buildIPv4(clientIP, dst, 17, udpPacket, uint16(binary.BigEndian.Uint32(xid[:])))})
	}
	r.stats.Requests++
	return out, true
}

// HandleServer accepts a reply from a configured server and returns the
// original DHCP payload in a client-facing Ethernet frame.
func (r *DHCPRelay) HandleServer(server netip.Addr, packet []byte) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	allowed := false
	for _, configured := range r.network.Relay.Servers {
		if configured == server {
			allowed = true
			break
		}
	}
	if !allowed {
		r.stats.Rejected++
		return nil, false
	}
	header, proto, src, dst, total, ok := parseIPv4(packet)
	if !ok || proto != 17 || total < header+8 {
		r.stats.Rejected++
		return nil, false
	}
	udp := packet[header:total]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if binary.BigEndian.Uint16(udp[:2]) != 67 || binary.BigEndian.Uint16(udp[2:4]) != 67 || udpLen < 8 || udpLen > len(udp) {
		r.stats.Rejected++
		return nil, false
	}
	reply := udp[8:udpLen]
	if !bytes.Equal(src[:], server.AsSlice()) || len(reply) < 240 || reply[0] != 2 || reply[1] != 1 || reply[2] != 6 || !bytes.Equal(reply[236:240], []byte{0x63, 0x82, 0x53, 0x63}) || !bytes.Equal(dst[:], r.network.Prefix.Addr().AsSlice()) || !bytes.Equal(reply[24:28], dst[:]) {
		r.stats.Rejected++
		return nil, false
	}
	var key relayKey
	copy(key.xid[:], reply[4:8])
	copy(key.mac[:], reply[28:34])
	transaction, ok := r.pending[key]
	if !ok || r.now().Sub(transaction.created) > relayTransactionTTL {
		delete(r.pending, key)
		r.stats.Rejected++
		return nil, false
	}
	options, valid := parseDHCPOptions(reply[240:])
	if !valid || len(options[53]) != 1 {
		r.stats.Rejected++
		return nil, false
	}
	delete(r.pending, key)
	var srcIP, dstIP [4]byte
	copy(srcIP[:], server.AsSlice())
	var dstMAC [6]byte
	copy(dstMAC[:], key.mac[:])
	broadcast := binary.BigEndian.Uint16(reply[10:12])&0x8000 != 0
	if broadcast {
		dstIP = [4]byte{255, 255, 255, 255}
		dstMAC = broadcastMAC
	} else {
		copy(dstIP[:], reply[16:20])
		if dstIP == [4]byte{} {
			copy(dstIP[:], reply[12:16])
		}
		if dstIP == [4]byte{} {
			dstIP = [4]byte{255, 255, 255, 255}
			dstMAC = broadcastMAC
		}
	}
	udpOut := buildUDP(srcIP, dstIP, 67, 68, reply)
	ipOut := buildIPv4(srcIP, dstIP, 17, udpOut, uint16(binary.BigEndian.Uint32(key.xid[:])))
	r.stats.Replies++
	return encodeEthernet(dstMAC, r.mac, ethIPv4, ipOut, r.network.VLANID), true
}

// Stats returns a consistent counter snapshot.
func (r *DHCPRelay) Stats() DHCPRelayStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *DHCPRelay) expireLocked(now time.Time) {
	for key, transaction := range r.pending {
		if now.Sub(transaction.created) > relayTransactionTTL {
			delete(r.pending, key)
			r.stats.Expired++
		}
	}
}
