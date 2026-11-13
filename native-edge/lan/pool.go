package lan

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"gamebond.local/nativeedge/atomicio"
)

// PoolLease is a DHCP lease assigned by a subnet DHCP server.
type PoolLease struct {
	Network  string     `json:"network"`
	IP       netip.Addr `json:"ip"`
	MAC      [6]byte    `json:"mac"`
	Hostname string     `json:"hostname,omitempty"`
	Granted  time.Time  `json:"granted"`
	Expires  time.Time  `json:"expires"`
}

// PoolLeaseTable persists leases independently of legacy fixed-device leases.
type PoolLeaseTable struct {
	mu          sync.Mutex
	path        string
	rows        map[string]PoolLease
	WriteErrors uint64
}

func poolLeaseKey(network string, ip netip.Addr) string { return network + "|" + ip.String() }

// OpenPoolLeaseTable loads a versioned local-network DHCP lease file. Missing or
// invalid files are treated as empty; the table is an optimization, not a startup
// dependency.
func OpenPoolLeaseTable(path string) *PoolLeaseTable {
	t := &PoolLeaseTable{path: path, rows: map[string]PoolLease{}}
	if path == "" {
		return t
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return t
	}
	var stored []PoolLease
	if json.Unmarshal(data, &stored) != nil {
		return t
	}
	for _, row := range stored {
		if row.Network == "" || !row.IP.Is4() || row.MAC == ([6]byte{}) || row.Expires.IsZero() {
			continue
		}
		t.rows[poolLeaseKey(row.Network, row.IP)] = row
	}
	return t
}

// GetByMAC returns the unexpired lease held by mac on network.
func (t *PoolLeaseTable) GetByMAC(network string, mac [6]byte) (PoolLease, bool) {
	return t.GetByMACAt(network, mac, time.Now())
}

// GetByMACAt returns a lease active at now.
func (t *PoolLeaseTable) GetByMACAt(network string, mac [6]byte, now time.Time) (PoolLease, bool) {
	if t == nil {
		return PoolLease{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, row := range t.rows {
		if row.Network == network && row.MAC == mac && now.Before(row.Expires) {
			return row, true
		}
	}
	return PoolLease{}, false
}

// GetByIP returns the unexpired lease for address on network.
func (t *PoolLeaseTable) GetByIP(network string, ip netip.Addr) (PoolLease, bool) {
	return t.GetByIPAt(network, ip, time.Now())
}

// GetByIPAt returns the lease for ip when it is active at now.
func (t *PoolLeaseTable) GetByIPAt(network string, ip netip.Addr, now time.Time) (PoolLease, bool) {
	if t == nil {
		return PoolLease{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	row, ok := t.rows[poolLeaseKey(network, ip)]
	return row, ok && now.Before(row.Expires)
}

// Put stores and persists a lease.
func (t *PoolLeaseTable) Put(row PoolLease) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, old := range t.rows {
		if old.Network == row.Network && old.MAC == row.MAC && key != poolLeaseKey(row.Network, row.IP) {
			delete(t.rows, key)
		}
	}
	t.rows[poolLeaseKey(row.Network, row.IP)] = row
	t.saveLocked()
}

// Release removes the lease held by mac on network.
func (t *PoolLeaseTable) Release(network string, mac [6]byte) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for key, row := range t.rows {
		if row.Network == network && row.MAC == mac {
			delete(t.rows, key)
			changed = true
		}
	}
	if changed {
		t.saveLocked()
	}
}

// Expire removes expired leases and persists only when the table changes.
func (t *PoolLeaseTable) Expire(now time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for key, row := range t.rows {
		if !now.Before(row.Expires) {
			delete(t.rows, key)
			changed = true
		}
	}
	if changed {
		t.saveLocked()
	}
}

// Rows returns a snapshot sorted by network then address.
func (t *PoolLeaseTable) Rows() []PoolLease {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rows := make([]PoolLease, 0, len(t.rows))
	for _, row := range t.rows {
		rows = append(rows, row)
	}
	sortPoolLeases(rows)
	return rows
}

func sortPoolLeases(rows []PoolLease) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Network != rows[j].Network {
			return rows[i].Network < rows[j].Network
		}
		return rows[i].IP.Compare(rows[j].IP) < 0
	})
}

func (t *PoolLeaseTable) saveLocked() {
	if t.path == "" {
		return
	}
	rows := make([]PoolLease, 0, len(t.rows))
	for _, row := range t.rows {
		rows = append(rows, row)
	}
	sortPoolLeases(rows)
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.WriteErrors++
		return
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
		t.WriteErrors++
		return
	}
	if err := atomicio.WriteFileAtomic(t.path, data, 0o600); err != nil {
		t.WriteErrors++
	}
}

type dhcpOffer struct {
	ip      netip.Addr
	xid     [4]byte
	expires time.Time
}

// DHCPStats reports DHCP server activity.
type DHCPStats struct {
	Offers, Acks, Naks, Releases, Malformed uint64
}

// DHCPServer serves a pool on one local network.
type DHCPServer struct {
	mu      sync.Mutex
	network NetworkConfig
	mac     [6]byte
	leases  *PoolLeaseTable
	now     func() time.Time
	offers  map[[6]byte]dhcpOffer
	stats   DHCPStats
}

// NewDHCPServer creates a DHCP server for a configured local network.
func NewDHCPServer(network NetworkConfig, mac [6]byte, leases *PoolLeaseTable, now func() time.Time) (*DHCPServer, error) {
	if network.DHCP == nil || !network.Prefix.IsValid() || !network.Prefix.Addr().Is4() || mac == ([6]byte{}) || mac[0]&1 != 0 {
		return nil, fmt.Errorf("network %q has invalid DHCP server settings", network.Name)
	}
	if now == nil {
		now = time.Now
	}
	return &DHCPServer{network: network, mac: mac, leases: leases, now: now, offers: map[[6]byte]dhcpOffer{}}, nil
}

// Handle processes a DHCP client Ethernet frame. Non-DHCP frames return
// handled=false; malformed DHCP frames are consumed and counted.
func (s *DHCPServer) Handle(frame []byte) (reply []byte, handled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(frame) < 14 || binary.BigEndian.Uint16(frame[12:14]) != ethIPv4 {
		return nil, false
	}
	ip := frame[14:]
	header, proto, src, dst, total, ok := parseIPv4(ip)
	if !ok || proto != 17 || total < header+8 {
		return nil, false
	}
	udp := ip[header:total]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if binary.BigEndian.Uint16(udp[:2]) != 68 || binary.BigEndian.Uint16(udp[2:4]) != 67 || udpLen < 8 || udpLen > len(udp) {
		return nil, false
	}
	request := udp[8:udpLen]
	if len(request) < 240 || request[0] != 1 || request[1] != 1 || request[2] != 6 || !bytes.Equal(request[236:240], []byte{0x63, 0x82, 0x53, 0x63}) {
		s.stats.Malformed++
		return nil, true
	}
	var chaddr [6]byte
	copy(chaddr[:], request[28:34])
	var srcMAC [6]byte
	copy(srcMAC[:], frame[6:12])
	if chaddr != srcMAC || chaddr == ([6]byte{}) || chaddr[0]&1 != 0 {
		s.stats.Malformed++
		return nil, true
	}
	source := netip.AddrFrom4(src)
	broadcast := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	if source != netip.AddrFrom4([4]byte{}) && !s.network.Prefix.Contains(source) {
		s.stats.Malformed++
		return nil, true
	}
	if netip.AddrFrom4(dst) != broadcast && netip.AddrFrom4(dst) != s.network.Prefix.Addr() {
		s.stats.Malformed++
		return nil, true
	}
	options, valid := parseDHCPOptions(request[240:])
	if !valid {
		s.stats.Malformed++
		return nil, true
	}
	kind := options[53]
	if len(kind) != 1 {
		s.stats.Malformed++
		return nil, true
	}
	now := s.now()
	if s.leases != nil {
		s.leases.Expire(now)
	}
	s.expireOffers(now)
	var xid [4]byte
	copy(xid[:], request[4:8])

	switch kind[0] {
	case 1: // DISCOVER
		address, ok := s.allocate(chaddr, netip.Addr{}, now)
		if !ok {
			return nil, true
		}
		s.offers[chaddr] = dhcpOffer{ip: address, xid: xid, expires: now.Add(60 * time.Second)}
		s.stats.Offers++
		return s.replyFrame(request, chaddr, 2, address), true
	case 3: // REQUEST
		if serverID := options[54]; len(serverID) == 4 && !bytes.Equal(serverID, s.network.Prefix.Addr().AsSlice()) {
			return nil, true // the client selected a different DHCP server
		}
		requested := netip.Addr{}
		if value := options[50]; len(value) == 4 {
			var a [4]byte
			copy(a[:], value)
			requested = netip.AddrFrom4(a)
		} else if !bytes.Equal(request[12:16], []byte{0, 0, 0, 0}) {
			var a [4]byte
			copy(a[:], request[12:16])
			requested = netip.AddrFrom4(a)
		}
		address, ok := s.allocate(chaddr, requested, now)
		if !ok || !requested.IsValid() || address != requested {
			s.stats.Naks++
			return s.replyFrame(request, chaddr, 6, netip.Addr{}), true
		}
		lease := PoolLease{Network: s.network.Name, IP: address, MAC: chaddr, Hostname: dhcpHostnameFromOptions(options), Granted: now, Expires: now.Add(time.Duration(s.network.DHCP.LeaseSeconds) * time.Second)}
		if s.leases != nil {
			s.leases.Put(lease)
		}
		delete(s.offers, chaddr)
		s.stats.Acks++
		return s.replyFrame(request, chaddr, 5, address), true
	case 7: // RELEASE
		if s.leases != nil {
			if lease, ok := s.leases.GetByMACAt(s.network.Name, chaddr, now); ok && bytes.Equal(request[12:16], lease.IP.AsSlice()) {
				s.leases.Release(s.network.Name, chaddr)
			}
		}
		delete(s.offers, chaddr)
		s.stats.Releases++
		return nil, true
	default:
		return nil, true
	}
}

// Stats returns a consistent DHCP counter snapshot.
func (s *DHCPServer) Stats() DHCPStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *DHCPServer) expireOffers(now time.Time) {
	for mac, offer := range s.offers {
		if !now.Before(offer.expires) {
			delete(s.offers, mac)
		}
	}
}

func (s *DHCPServer) allocate(mac [6]byte, requested netip.Addr, now time.Time) (netip.Addr, bool) {
	pool := s.network.DHCP
	if reservation, ok := reservedAddress(pool, mac); ok {
		if requested.IsValid() && requested != reservation {
			return netip.Addr{}, false
		}
		if s.available(reservation, mac, now) {
			return reservation, true
		}
		return netip.Addr{}, false
	}
	if s.leases != nil {
		if lease, ok := s.leases.GetByMACAt(s.network.Name, mac, now); ok && s.inPool(lease.IP) && (!requested.IsValid() || requested == lease.IP) {
			return lease.IP, true
		}
	}
	if requested.IsValid() {
		if s.inPool(requested) && s.available(requested, mac, now) {
			return requested, true
		}
		return netip.Addr{}, false
	}
	for n := ipv4Number(pool.Start); n <= ipv4Number(pool.End); n++ {
		address := uint32Addr(n)
		if s.available(address, mac, now) {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func (s *DHCPServer) available(ip netip.Addr, mac [6]byte, now time.Time) bool {
	for _, reservation := range s.network.DHCP.Reservations {
		if reservation.IP == ip && reservation.MAC != mac {
			return false
		}
	}
	if s.leases != nil {
		if row, ok := s.leases.GetByIPAt(s.network.Name, ip, now); ok && row.MAC != mac {
			return false
		}
	}
	for owner, offer := range s.offers {
		if offer.ip == ip && owner != mac {
			return false
		}
	}
	return true
}

func (s *DHCPServer) inPool(ip netip.Addr) bool {
	return ip.Is4() && ip.Compare(s.network.DHCP.Start) >= 0 && ip.Compare(s.network.DHCP.End) <= 0
}

func reservedAddress(pool *DHCPPoolConfig, mac [6]byte) (netip.Addr, bool) {
	for _, r := range pool.Reservations {
		if r.MAC == mac {
			return r.IP, true
		}
	}
	return netip.Addr{}, false
}

func parseDHCPOptions(data []byte) (map[byte][]byte, bool) {
	out := map[byte][]byte{}
	ended := false
	for i := 0; i < len(data); {
		kind := data[i]
		if kind == 255 {
			ended = true
			break
		}
		if kind == 0 {
			i++
			continue
		}
		if i+1 >= len(data) || i+2+int(data[i+1]) > len(data) {
			return nil, false
		}
		if _, exists := out[kind]; exists {
			return nil, false
		}
		out[kind] = data[i+2 : i+2+int(data[i+1])]
		i += 2 + int(data[i+1])
	}
	return out, ended
}

func (s *DHCPServer) replyFrame(request []byte, chaddr [6]byte, message byte, yiaddr netip.Addr) []byte {
	body := make([]byte, 240)
	body[0], body[1], body[2] = 2, 1, 6
	copy(body[4:8], request[4:8])
	copy(body[8:10], request[8:10])
	copy(body[10:12], request[10:12])
	if yiaddr.Is4() {
		a := yiaddr.As4()
		copy(body[16:20], a[:])
	}
	server := s.network.Prefix.Addr().As4()
	copy(body[20:24], server[:])
	copy(body[28:34], chaddr[:])
	copy(body[236:240], []byte{0x63, 0x82, 0x53, 0x63})
	options := []byte{53, 1, message, 54, 4}
	options = append(options, server[:]...)
	if message != 6 {
		lease := uint32(s.network.DHCP.LeaseSeconds)
		options = append(options, 51, 4)
		options = binary.BigEndian.AppendUint32(options, lease)
		options = append(options, 1, 4)
		mask := prefixMask(s.network.Prefix.Bits())
		options = append(options, mask[:]...)
		options = append(options, 3, 4)
		options = append(options, server[:]...)
		dns := make([]byte, 0, 4*len(s.network.DHCP.DNS))
		for _, address := range s.network.DHCP.DNS {
			a := address.As4()
			dns = append(dns, a[:]...)
		}
		options = append(options, 6, byte(len(dns)))
		options = append(options, dns...)
	}
	options = append(options, 255)
	body = append(body, options...)
	serverIP := s.network.Prefix.Addr().As4()
	broadcast := [4]byte{255, 255, 255, 255}
	udp := buildUDP(serverIP, broadcast, 67, 68, body)
	ip := buildIPv4(serverIP, broadcast, 17, udp, uint16(binary.BigEndian.Uint32(request[4:8])))
	frame := make([]byte, 14, 14+len(ip))
	copy(frame[:6], broadcastMAC[:])
	copy(frame[6:12], s.mac[:])
	binary.BigEndian.PutUint16(frame[12:14], ethIPv4)
	return append(frame, ip...)
}

func prefixMask(bits int) [4]byte {
	var mask [4]byte
	for i := 0; i < bits; i++ {
		mask[i/8] |= 1 << (7 - uint(i%8))
	}
	return mask
}

func uint32Addr(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func dhcpHostnameFromOptions(options map[byte][]byte) string {
	value := options[12]
	if len(value) > 255 {
		value = value[:255]
	}
	for _, b := range value {
		if b < 0x20 || b > 0x7e {
			return ""
		}
	}
	return string(value)
}
