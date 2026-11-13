package lan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	MaxLocalNetworks = 16
	MaxStaticRoutes  = 128
	MaxDHCPPoolSize  = 4096
	MaxDHCPServers   = 3
)

// NetworkConfig describes one IPv4 network attached to a dedicated adapter.
// Prefix.Addr is the gateway address owned by the local router.
type NetworkConfig struct {
	Name           string
	InterfaceID    string
	InterfaceName  string
	InterfaceIndex int
	Prefix         netip.Prefix
	VLANID         int
	DHCP           *DHCPPoolConfig
	Relay          *DHCPRelayConfig
	ForwardTo      []string
}

// Reservation binds one client hardware address to a fixed address in the pool.
type Reservation struct {
	MAC  [6]byte
	IP   netip.Addr
	Name string
}

// DHCPPoolConfig is the dynamic address range and DHCP options for a network.
type DHCPPoolConfig struct {
	Start        netip.Addr
	End          netip.Addr
	LeaseSeconds int
	DNS          []netip.Addr
	Reservations []Reservation
}

// DHCPRelayConfig lists the only DHCP servers this network may relay to.
type DHCPRelayConfig struct {
	Servers []netip.Addr
}

// StaticRoute forwards a destination prefix through a directly-connected next hop.
type StaticRoute struct {
	Destination netip.Prefix
	NextHop     netip.Addr
	Interface   string
}

// LocalConfig is the normalized local network and static route configuration.
type LocalConfig struct {
	Networks []NetworkConfig
	Routes   []StaticRoute
}

// LoadLocalConfig parses the optional local_networks and static_routes arrays
// and rejects conflicts with uplinks and legacy lan_devices before runtime opens
// any adapter. Empty or null arrays are treated as absent.
func LoadLocalConfig(networksRaw, routesRaw []byte, uplinkIDs, deviceIDs []string, uplinkIndices, deviceIndices []int) (LocalConfig, error) {
	var out LocalConfig
	networkRows, err := decodeRows(networksRaw, MaxLocalNetworks, "local_networks")
	if err != nil {
		return out, err
	}
	routeRows, err := decodeRows(routesRaw, MaxStaticRoutes, "static_routes")
	if err != nil {
		return out, err
	}

	usedIDs := map[string]string{}
	for _, id := range uplinkIDs {
		if id != "" {
			usedIDs["id:"+strings.ToLower(id)] = "VPN uplink"
		}
	}
	for _, id := range deviceIDs {
		if id != "" {
			key := "id:" + strings.ToLower(id)
			if strings.HasPrefix(strings.ToLower(id), "name:") {
				key = "name:" + strings.ToLower(strings.TrimPrefix(id, "name:"))
			}
			usedIDs[key] = "legacy LAN device"
		}
	}
	usedIndices := map[int]string{}
	usedIndexIdentity := map[int]string{}
	for _, idx := range uplinkIndices {
		if idx > 0 {
			usedIndices[idx] = "VPN uplink"
		}
	}
	for _, idx := range deviceIndices {
		if idx > 0 {
			usedIndices[idx] = "legacy LAN device"
		}
	}

	names := map[string]bool{}
	prefixes := make([]netip.Prefix, 0, len(networkRows))
	attachments := map[string]map[int]string{}
	for i, row := range networkRows {
		n, err := parseNetwork(row, i)
		if err != nil {
			return out, err
		}
		key := strings.ToLower(n.Name)
		if names[key] {
			return out, fmt.Errorf("local_networks[%d].name duplicates another network", i)
		}
		names[key] = true
		for _, p := range prefixes {
			if prefixesOverlap(p, n.Prefix) {
				return out, fmt.Errorf("local_networks[%d].prefix overlaps another local network", i)
			}
		}
		prefixes = append(prefixes, n.Prefix)

		identity := networkIdentity(n)
		if owner := usedIDs[identity]; owner != "" {
			if owner != "local network" || n.VLANID == 0 {
				return out, fmt.Errorf("local network %q reuses an adapter assigned to %s", n.Name, owner)
			}
		}
		if n.InterfaceIndex > 0 {
			if owner := usedIndices[n.InterfaceIndex]; owner != "" {
				return out, fmt.Errorf("local network %q reuses an adapter index assigned to %s", n.Name, owner)
			}
		}
		if attached := attachments[identity]; attached != nil {
			if n.VLANID == 0 {
				return out, fmt.Errorf("local network %q shares an adapter without a VLAN ID", n.Name)
			}
			if _, exists := attached[n.VLANID]; exists {
				return out, fmt.Errorf("local networks reuse VLAN %d on one adapter", n.VLANID)
			}
			attached[n.VLANID] = n.Name
		} else {
			attachments[identity] = map[int]string{n.VLANID: n.Name}
		}
		if n.InterfaceIndex > 0 {
			if old, exists := usedIndices[n.InterfaceIndex]; exists {
				// Multiple VLANs may share a trunk index; an untagged interface may not.
				if old != "local network" || n.VLANID == 0 || usedIndexIdentity[n.InterfaceIndex] != identity {
					return out, fmt.Errorf("local network %q reuses interface index %d", n.Name, n.InterfaceIndex)
				}
			} else {
				usedIndices[n.InterfaceIndex] = "local network"
				usedIndexIdentity[n.InterfaceIndex] = identity
			}
		}
		if n.InterfaceID != "" {
			usedIDs[identity] = "local network"
		}
		out.Networks = append(out.Networks, n)
	}

	// Treat a configured network pair as bidirectional. Either side may declare
	// the pair; normalize the graph so forwarding behavior is deterministic.
	byName := make(map[string]int, len(out.Networks))
	for i := range out.Networks {
		byName[strings.ToLower(out.Networks[i].Name)] = i
	}
	pairs := map[string]bool{}
	for i := range out.Networks {
		for _, target := range out.Networks[i].ForwardTo {
			j, ok := byName[strings.ToLower(target)]
			if !ok {
				return out, fmt.Errorf("local_networks[%d].forward_to references unknown network %q", i, target)
			}
			if i == j {
				return out, fmt.Errorf("local_networks[%d].forward_to cannot reference itself", i)
			}
			a, b := i, j
			if a > b {
				a, b = b, a
			}
			pairs[fmt.Sprintf("%d:%d", a, b)] = true
		}
	}
	for pair := range pairs {
		var a, b int
		_, _ = fmt.Sscanf(pair, "%d:%d", &a, &b)
		out.Networks[a].ForwardTo = appendUniqueFold(out.Networks[a].ForwardTo, out.Networks[b].Name)
		out.Networks[b].ForwardTo = appendUniqueFold(out.Networks[b].ForwardTo, out.Networks[a].Name)
	}
	for i := range out.Networks {
		sort.Slice(out.Networks[i].ForwardTo, func(a, b int) bool {
			return strings.ToLower(out.Networks[i].ForwardTo[a]) < strings.ToLower(out.Networks[i].ForwardTo[b])
		})
	}

	routePrefixes := map[netip.Prefix]bool{}
	for i, row := range routeRows {
		route, err := parseStaticRoute(row, i, out.Networks)
		if err != nil {
			return out, err
		}
		if routePrefixes[route.Destination] {
			return out, fmt.Errorf("static_routes[%d].destination duplicates another route", i)
		}
		routePrefixes[route.Destination] = true
		for _, network := range out.Networks {
			if prefixesOverlap(route.Destination, network.Prefix.Masked()) {
				return out, fmt.Errorf("static_routes[%d].destination overlaps local network %q", i, network.Name)
			}
		}
		out.Routes = append(out.Routes, route)
	}
	return out, nil
}

func decodeRows(raw []byte, max int, field string) ([]map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil || rows == nil || len(rows) > max {
		return nil, fmt.Errorf("%s must be a list of at most %d objects", field, max)
	}
	for i, row := range rows {
		if row == nil {
			return nil, fmt.Errorf("%s[%d] must be an object", field, i)
		}
	}
	return rows, nil
}

func checkKeys(row map[string]json.RawMessage, field string, allowed ...string) error {
	known := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		known[key] = true
	}
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !known[key] {
			return fmt.Errorf("%s has unknown field %q", field, key)
		}
	}
	return nil
}

func decodeRequired[T any](row map[string]json.RawMessage, key, field string, into *T) error {
	raw, ok := row[key]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s.%s is required", field, key)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s.%s has an invalid value", field, key)
	}
	return nil
}

func decodeOptional[T any](row map[string]json.RawMessage, key, field string, into *T) (bool, error) {
	raw, ok := row[key]
	if !ok {
		return false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, fmt.Errorf("%s.%s cannot be null", field, key)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return false, fmt.Errorf("%s.%s has an invalid value", field, key)
	}
	return true, nil
}

func parseNetwork(row map[string]json.RawMessage, index int) (NetworkConfig, error) {
	var n NetworkConfig
	field := fmt.Sprintf("local_networks[%d]", index)
	if err := checkKeys(row, field, "name", "interface_id", "interface_name", "interface_index", "prefix", "vlan_id", "dhcp", "relay", "forward_to"); err != nil {
		return n, err
	}
	if err := decodeRequired(row, "name", field, &n.Name); err != nil || !nameRe.MatchString(n.Name) {
		return n, fmt.Errorf("%s.name must be 1-32 letters, digits, spaces or ._()-", field)
	}
	if err := decodeOptionalString(row, "interface_id", field, &n.InterfaceID); err != nil {
		return n, err
	}
	if err := decodeOptionalString(row, "interface_name", field, &n.InterfaceName); err != nil {
		return n, err
	}
	if (n.InterfaceID == "") == (n.InterfaceName == "") {
		return n, fmt.Errorf("%s needs exactly one of interface_id or interface_name", field)
	}
	if n.InterfaceID != "" && !guidRe.MatchString(strings.ToLower(n.InterfaceID)) {
		return n, fmt.Errorf("%s.interface_id must be a Windows adapter GUID in braces", field)
	}
	if n.InterfaceName != "" && !ifaRe.MatchString(n.InterfaceName) {
		return n, fmt.Errorf("%s.interface_name must be a valid interface name", field)
	}
	if _, err := decodeOptional(row, "interface_index", field, &n.InterfaceIndex); err != nil || n.InterfaceIndex < 0 {
		return n, fmt.Errorf("%s.interface_index must be a nonnegative integer", field)
	}
	var prefixText string
	if err := decodeRequired(row, "prefix", field, &prefixText); err != nil {
		return n, err
	}
	prefix, err := netip.ParsePrefix(prefixText)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return n, fmt.Errorf("%s.prefix must be an IPv4 gateway address with prefix length /8 through /30", field)
	}
	if !usableHost(prefix, prefix.Addr()) {
		return n, fmt.Errorf("%s.prefix address must be a usable host address", field)
	}
	n.Prefix = prefix
	if _, err := decodeOptional(row, "vlan_id", field, &n.VLANID); err != nil || n.VLANID < 0 || n.VLANID > 4094 {
		return n, fmt.Errorf("%s.vlan_id must be between 1 and 4094 when present", field)
	}
	if _, has := row["vlan_id"]; has && n.VLANID == 0 {
		return n, fmt.Errorf("%s.vlan_id must be between 1 and 4094", field)
	}
	if raw, ok := row["dhcp"]; ok {
		pool, err := parseDHCPPool(raw, field+".dhcp", n.Prefix)
		if err != nil {
			return n, err
		}
		n.DHCP = &pool
	}
	if raw, ok := row["relay"]; ok {
		relay, err := parseDHCPRelay(raw, field+".relay")
		if err != nil {
			return n, err
		}
		n.Relay = &relay
	}
	if n.DHCP != nil && n.Relay != nil {
		return n, fmt.Errorf("%s cannot configure both dhcp and relay", field)
	}
	if _, err := decodeOptional(row, "forward_to", field, &n.ForwardTo); err != nil {
		return n, fmt.Errorf("%s.forward_to must be a list of network names", field)
	}
	seen := map[string]bool{}
	for _, target := range n.ForwardTo {
		if !nameRe.MatchString(target) || seen[strings.ToLower(target)] {
			return n, fmt.Errorf("%s.forward_to contains an invalid or duplicate network name", field)
		}
		seen[strings.ToLower(target)] = true
	}
	return n, nil
}

func decodeOptionalString(row map[string]json.RawMessage, key, field string, into *string) error {
	_, err := decodeOptional(row, key, field, into)
	return err
}

func parseDHCPPool(raw json.RawMessage, field string, prefix netip.Prefix) (DHCPPoolConfig, error) {
	var pool DHCPPoolConfig
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil || row == nil {
		return pool, fmt.Errorf("%s must be an object", field)
	}
	if err := checkKeys(row, field, "pool_start", "pool_end", "lease_seconds", "dns", "reservations"); err != nil {
		return pool, err
	}
	var startText, endText string
	if err := decodeRequired(row, "pool_start", field, &startText); err != nil {
		return pool, err
	}
	if err := decodeRequired(row, "pool_end", field, &endText); err != nil {
		return pool, err
	}
	var err error
	pool.Start, err = parseAddr(startText, field+".pool_start")
	if err != nil {
		return pool, err
	}
	pool.End, err = parseAddr(endText, field+".pool_end")
	if err != nil {
		return pool, err
	}
	if !usableHost(prefix, pool.Start) || !usableHost(prefix, pool.End) || pool.Start.Compare(pool.End) > 0 || pool.Start == prefix.Addr() || pool.End == prefix.Addr() {
		return pool, fmt.Errorf("%s pool range must be ordered usable host addresses in the network and exclude its gateway", field)
	}
	first, last := ipv4Number(pool.Start), ipv4Number(pool.End)
	if last-first+1 > MaxDHCPPoolSize {
		return pool, fmt.Errorf("%s pool may contain at most %d addresses", field, MaxDHCPPoolSize)
	}
	pool.LeaseSeconds = DefaultLease
	if _, err := decodeOptional(row, "lease_seconds", field, &pool.LeaseSeconds); err != nil || pool.LeaseSeconds < 60 || pool.LeaseSeconds > 30*24*60*60 {
		return pool, fmt.Errorf("%s.lease_seconds must be between 60 and 2592000", field)
	}
	pool.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	if rawDNS, ok := row["dns"]; ok {
		var values []string
		if err := json.Unmarshal(rawDNS, &values); err != nil || len(values) < 1 || len(values) > 3 {
			return pool, fmt.Errorf("%s.dns must contain one to three unicast IPv4 addresses", field)
		}
		pool.DNS = nil
		seen := map[netip.Addr]bool{}
		for _, value := range values {
			a, err := parseAddr(value, field+".dns")
			if err != nil || seen[a] {
				return pool, fmt.Errorf("%s.dns must contain distinct unicast IPv4 addresses", field)
			}
			seen[a] = true
			pool.DNS = append(pool.DNS, a)
		}
	}
	if rawReservations, ok := row["reservations"]; ok {
		var reservations []map[string]json.RawMessage
		if err := json.Unmarshal(rawReservations, &reservations); err != nil || reservations == nil || len(reservations) > MaxDHCPPoolSize {
			return pool, fmt.Errorf("%s.reservations must be a list", field)
		}
		macs, ips := map[[6]byte]bool{}, map[netip.Addr]bool{}
		for i, item := range reservations {
			r, err := parseReservation(item, fmt.Sprintf("%s.reservations[%d]", field, i), prefix, pool.Start, pool.End)
			if err != nil {
				return pool, err
			}
			if macs[r.MAC] || ips[r.IP] {
				return pool, fmt.Errorf("%s.reservations[%d] duplicates a MAC or address", field, i)
			}
			macs[r.MAC], ips[r.IP] = true, true
			pool.Reservations = append(pool.Reservations, r)
		}
	}
	return pool, nil
}

func parseReservation(row map[string]json.RawMessage, field string, prefix netip.Prefix, start, end netip.Addr) (Reservation, error) {
	var out Reservation
	if row == nil {
		return out, fmt.Errorf("%s must be an object", field)
	}
	if err := checkKeys(row, field, "mac", "ip", "name"); err != nil {
		return out, err
	}
	var macText, ipText string
	if err := decodeRequired(row, "mac", field, &macText); err != nil {
		return out, err
	}
	if err := decodeRequired(row, "ip", field, &ipText); err != nil {
		return out, err
	}
	var err error
	out.MAC, err = ParseMAC(macText)
	if err != nil || out.MAC == ([6]byte{}) || out.MAC[0]&1 != 0 {
		return out, fmt.Errorf("%s.mac must be a unicast MAC address", field)
	}
	out.IP, err = parseAddr(ipText, field+".ip")
	if err != nil || !usableHost(prefix, out.IP) || out.IP == prefix.Addr() || out.IP.Compare(start) < 0 || out.IP.Compare(end) > 0 {
		return out, fmt.Errorf("%s.ip must be a usable address inside the DHCP pool", field)
	}
	if err := decodeOptionalString(row, "name", field, &out.Name); err != nil {
		return out, err
	}
	if out.Name != "" && !nameRe.MatchString(out.Name) {
		return out, fmt.Errorf("%s.name is invalid", field)
	}
	return out, nil
}

func parseDHCPRelay(raw json.RawMessage, field string) (DHCPRelayConfig, error) {
	var relay DHCPRelayConfig
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil || row == nil {
		return relay, fmt.Errorf("%s must be an object", field)
	}
	if err := checkKeys(row, field, "servers"); err != nil {
		return relay, err
	}
	var values []string
	if err := decodeRequired(row, "servers", field, &values); err != nil || len(values) < 1 || len(values) > MaxDHCPServers {
		return relay, fmt.Errorf("%s.servers must contain one to %d unicast IPv4 addresses", field, MaxDHCPServers)
	}
	seen := map[netip.Addr]bool{}
	for _, value := range values {
		a, err := parseAddr(value, field+".servers")
		if err != nil || seen[a] {
			return relay, fmt.Errorf("%s.servers must contain distinct unicast IPv4 addresses", field)
		}
		seen[a] = true
		relay.Servers = append(relay.Servers, a)
	}
	return relay, nil
}

func parseStaticRoute(row map[string]json.RawMessage, index int, networks []NetworkConfig) (StaticRoute, error) {
	var route StaticRoute
	field := fmt.Sprintf("static_routes[%d]", index)
	if err := checkKeys(row, field, "destination", "next_hop", "interface"); err != nil {
		return route, err
	}
	var destination, nextHop string
	if err := decodeRequired(row, "destination", field, &destination); err != nil {
		return route, err
	}
	if err := decodeRequired(row, "next_hop", field, &nextHop); err != nil {
		return route, err
	}
	if err := decodeRequired(row, "interface", field, &route.Interface); err != nil {
		return route, err
	}
	prefix, err := netip.ParsePrefix(destination)
	if err != nil || !prefix.Addr().Is4() {
		return route, fmt.Errorf("%s.destination must be an IPv4 prefix", field)
	}
	route.Destination = prefix.Masked()
	route.NextHop, err = parseAddr(nextHop, field+".next_hop")
	if err != nil {
		return route, err
	}
	var attached *NetworkConfig
	for i := range networks {
		if strings.EqualFold(networks[i].Name, route.Interface) {
			attached = &networks[i]
			break
		}
	}
	if attached == nil {
		return route, fmt.Errorf("%s.interface must name a configured local network", field)
	}
	if !usableHost(attached.Prefix, route.NextHop) || route.NextHop == attached.Prefix.Addr() {
		return route, fmt.Errorf("%s.next_hop must be a usable host on interface %q", field, attached.Name)
	}
	if route.Destination.Contains(route.NextHop) {
		return route, fmt.Errorf("%s.next_hop is covered by its destination route", field)
	}
	route.Interface = attached.Name
	return route, nil
}

func parseAddr(value, field string) (netip.Addr, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || !a.Is4() || !isUnicastAddress(a) {
		return netip.Addr{}, fmt.Errorf("%s must be a unicast IPv4 address", field)
	}
	return a, nil
}

func isUnicastAddress(a netip.Addr) bool {
	return a.IsValid() && a.Is4() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func usableHost(prefix netip.Prefix, address netip.Addr) bool {
	if !address.Is4() || !prefix.IsValid() || !prefix.Contains(address) || prefix.Bits() > 30 {
		return false
	}
	network := prefix.Masked().Addr().As4()
	broadcast := network
	for bit := prefix.Bits(); bit < 32; bit++ {
		broadcast[bit/8] |= 1 << (7 - uint(bit%8))
	}
	a := address.As4()
	return a != network && a != broadcast
}

func ipv4Number(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func prefixesOverlap(a, b netip.Prefix) bool {
	if !a.IsValid() || !b.IsValid() || !a.Addr().Is4() || !b.Addr().Is4() {
		return false
	}
	return a.Contains(b.Masked().Addr()) || b.Contains(a.Masked().Addr())
}

func networkIdentity(n NetworkConfig) string {
	if n.InterfaceID != "" {
		return "id:" + strings.ToLower(n.InterfaceID)
	}
	return "name:" + strings.ToLower(n.InterfaceName)
}

// Identity returns the stable adapter key used by the local frame dispatcher.
func (n NetworkConfig) Identity() string { return networkIdentity(n) }

func appendUniqueFold(values []string, value string) []string {
	for _, old := range values {
		if strings.EqualFold(old, value) {
			return values
		}
	}
	return append(values, value)
}
