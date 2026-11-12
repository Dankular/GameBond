package lan

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const MaxDevices = 4

var (
	macRe  = regexp.MustCompile(`^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$`)
	guidRe = regexp.MustCompile(`^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)
	nameRe = regexp.MustCompile(`^[A-Za-z0-9 ._()-]{1,32}$`)
	ifaRe  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

// ParseMAC accepts aa:bb:cc:dd:ee:ff or aa-bb-... in either case.
func ParseMAC(s string) ([6]byte, error) {
	var m [6]byte
	l := strings.ToLower(s)
	if !macRe.MatchString(l) {
		return m, errors.New("MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	_, err := fmt.Sscanf(strings.NewReplacer(":", "", "-", "").Replace(l), "%02x%02x%02x%02x%02x%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5])
	return m, err
}

// DeviceConfig is one validated lan_devices entry.
type DeviceConfig struct {
	Name           string
	TunnelIP       netip.Addr
	InterfaceID    string
	InterfaceIndex int
	InterfaceName  string
	DeviceMAC      string
	DNS            []netip.Addr
	// UDPDirect sends the device's public UDP straight out the first uplink
	// (workstation-side NAT) instead of through the tunnel; TCP stays tunneled.
	UDPDirect bool
	// Redundancy attaches the device through two adapters as a RedBox: "prp" (two parallel
	// LANs, RCT trailer) or "hsr" (ring ends, HSR tag). The second adapter is named by
	// RedundantInterfaceID (Windows) or RedundantInterfaceName (Linux). Empty: one adapter.
	Redundancy                                      string
	RedundantInterfaceID, RedundantInterfaceName string
}

// Identity is the adapter identity, case-folded.
func (d DeviceConfig) Identity() string {
	if d.InterfaceID != "" {
		return strings.ToLower(d.InterfaceID)
	}
	return strings.ToLower(d.InterfaceName)
}

func isUnicastV4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, false
	}
	return a, true
}

func validateTunnelIP(ip, client netip.Addr) error {
	subnet := subnetOf(client)
	b := ip.As4()
	if !subnet.Contains(ip) || b[3] == 0 || b[3] == 1 || b[3] == 255 || ip == client {
		return fmt.Errorf("%s is not a usable device address in %s (not .0, .1, .255 or the client address)", ip, subnet)
	}
	return nil
}

// LoadDevices validates a client's lan_devices (python load_lan_devices).
// uplinkIDs/uplinkIndices are the bonded uplinks the adapters must not reuse.
func LoadDevices(raw json.RawMessage, client netip.Addr, uplinkIDs []string, uplinkIndices []int) ([]DeviceConfig, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) > MaxDevices {
		return nil, fmt.Errorf("lan_devices must be a list of at most %d devices", MaxDevices)
	}
	var devices []DeviceConfig
	for _, e := range entries {
		for k := range e {
			switch k {
			case "name", "tunnel_ip", "interface_id", "interface_index", "interface_name", "device_mac", "dns", "udp_direct", "redundancy", "redundant_interface_id", "redundant_interface_name":
			default:
				return nil, fmt.Errorf("Unknown lan_devices field: %s", k)
			}
		}
		var d DeviceConfig
		get := func(key string, into any) error {
			if v, ok := e[key]; ok {
				return json.Unmarshal(v, into)
			}
			return nil
		}
		var tip string
		var dns []string
		idx := 0
		for key, into := range map[string]any{"name": &d.Name, "tunnel_ip": &tip, "interface_id": &d.InterfaceID, "interface_name": &d.InterfaceName, "device_mac": &d.DeviceMAC, "interface_index": &idx, "redundancy": &d.Redundancy, "redundant_interface_id": &d.RedundantInterfaceID, "redundant_interface_name": &d.RedundantInterfaceName} {
			if err := get(key, into); err != nil {
				return nil, fmt.Errorf("invalid lan_devices %s", key)
			}
		}
		if err := get("udp_direct", &d.UDPDirect); err != nil {
			return nil, errors.New("LAN device udp_direct must be true or false")
		}
		if _, ok := e["dns"]; ok {
			if err := get("dns", &dns); err != nil {
				return nil, errors.New("LAN device dns must list one to three unicast IPv4 addresses")
			}
		} else {
			dns = []string{"1.1.1.1", "8.8.8.8"}
		}
		d.InterfaceIndex = idx
		if !nameRe.MatchString(d.Name) {
			return nil, errors.New("LAN device name must be 1-32 letters, digits, spaces or ._()-")
		}
		ip, err := netip.ParseAddr(tip)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("invalid tunnel_ip %q", tip)
		}
		if err := validateTunnelIP(ip, client); err != nil {
			return nil, err
		}
		d.TunnelIP = ip
		if d.InterfaceID == "" && d.InterfaceName == "" {
			return nil, errors.New("LAN device needs interface_id (Windows) or interface_name (Linux)")
		}
		if d.InterfaceID != "" && !guidRe.MatchString(strings.ToLower(d.InterfaceID)) {
			return nil, errors.New("LAN device interface_id must be a Windows adapter GUID in braces")
		}
		if d.InterfaceName != "" && !ifaRe.MatchString(d.InterfaceName) {
			return nil, errors.New("LAN device interface_name must be a valid Linux interface name")
		}
		if d.RedundantInterfaceID != "" || d.RedundantInterfaceName != "" {
			if d.Redundancy == "" {
				d.Redundancy = "prp"
			}
			if strings.EqualFold(d.RedundantInterfaceID, d.InterfaceID) && strings.EqualFold(d.RedundantInterfaceName, d.InterfaceName) {
				return nil, errors.New("LAN device redundant adapter must differ from its first adapter")
			}
		}
		if d.Redundancy != "" && d.Redundancy != "prp" && d.Redundancy != "hsr" {
			return nil, errors.New("LAN device redundancy must be \"prp\" or \"hsr\"")
		}
		if d.Redundancy != "" && d.RedundantInterfaceID == "" && d.RedundantInterfaceName == "" {
			return nil, errors.New("LAN device redundancy needs redundant_interface_id or redundant_interface_name")
		}
		if d.InterfaceIndex < 0 {
			return nil, errors.New("LAN device interface_index must be a nonnegative integer")
		}
		if d.DeviceMAC != "" {
			if _, err := ParseMAC(d.DeviceMAC); err != nil {
				return nil, err
			}
		}
		if len(dns) < 1 || len(dns) > 3 {
			return nil, errors.New("LAN device dns must list one to three unicast IPv4 addresses")
		}
		for _, s := range dns {
			a, ok := isUnicastV4(s)
			if !ok {
				return nil, errors.New("LAN device dns must list one to three unicast IPv4 addresses")
			}
			d.DNS = append(d.DNS, a)
		}
		devices = append(devices, d)
	}
	distinct := func(what string, vals []string) error {
		seen := map[string]bool{}
		for _, v := range vals {
			if seen[v] {
				return fmt.Errorf("lan_devices must have distinct %s", what)
			}
			seen[v] = true
		}
		return nil
	}
	var names, ips, ids, macs []string
	for _, d := range devices {
		names = append(names, strings.ToLower(d.Name))
		ips = append(ips, d.TunnelIP.String())
		ids = append(ids, d.Identity())
	}
	for _, c := range []struct {
		what string
		vals []string
	}{{"name", names}, {"tunnel_ip", ips}} {
		if err := distinct(c.what, c.vals); err != nil {
			return nil, err
		}
	}
	// Several devices may share one adapter (PS5 and laptop behind an access
	// point); unpinned ones claim a device by DHCP request or tunnel-IP traffic.
	// Python compares the lower-cased strings as written, so aa:.. and aa-.. differ.
	for _, d := range devices {
		if d.DeviceMAC != "" {
			macs = append(macs, strings.ToLower(d.DeviceMAC))
		}
	}
	if err := distinct("device_mac values", macs); err != nil {
		return nil, err
	}
	ids2 := map[string]bool{}
	for _, u := range uplinkIDs {
		if u != "" {
			ids2[strings.ToLower(u)] = true
		}
	}
	idxs := map[int]bool{}
	for _, i := range uplinkIndices {
		idxs[i] = true
	}
	for _, d := range devices {
		if d.InterfaceID != "" && ids2[strings.ToLower(d.InterfaceID)] {
			return nil, fmt.Errorf("%s: adapter is already selected as a bonded uplink", d.Name)
		}
		if d.InterfaceIndex != 0 && idxs[d.InterfaceIndex] && d.InterfaceID == "" {
			return nil, fmt.Errorf("%s: adapter is already selected as a bonded uplink", d.Name)
		}
	}
	return devices, nil
}
