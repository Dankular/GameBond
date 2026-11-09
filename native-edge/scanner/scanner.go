// Package scanner is the Go port of gamebond/network_scanner.py: a passive
// neighbor inventory plus an explicit, bounded, source-bound ICMP discovery job.
// Taking an inventory never probes the LAN; only DiscoveryJob.Start does.
package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Adapter is one preferred IPv4 address on a local adapter.
type Adapter struct {
	Index           int    `json:"index"`
	Name            string `json:"name"`
	Address         string `json:"address"`
	PrefixLength    int    `json:"prefix_length"`
	Subnet          string `json:"subnet"`
	DiscoverySubnet string `json:"discovery_subnet"`
	Up              bool   `json:"up"`
	MAC             string `json:"mac"`
	Description     string `json:"description"`
}

// Device is one neighbor-cache entry.
type Device struct {
	InterfaceIndex int     `json:"interface_index"`
	Address        string  `json:"address"`
	MAC            string  `json:"mac"`
	State          string  `json:"state"`
	Source         string  `json:"source"`
	ReachableNow   bool    `json:"reachable_now"`
	Hostname       *string `json:"hostname"`
	Vendor         *string `json:"vendor"`
	FirstSeen      float64 `json:"first_seen,omitempty"`
	LastSeen       float64 `json:"last_seen,omitempty"`
}

type Coverage struct {
	AdaptersReturned     int  `json:"adapters_returned"`
	DevicesReturned      int  `json:"devices_returned"`
	AdapterLimitReached  bool `json:"adapter_limit_reached"`
	NeighborLimitReached bool `json:"neighbor_limit_reached"`
}

// Inventory is the normalized passive inventory.
type Inventory struct {
	ObservedAt  float64   `json:"observed_at"`
	Adapters    []Adapter `json:"adapters"`
	Devices     []Device  `json:"devices"`
	Coverage    Coverage  `json:"coverage"`
	ActiveProbe bool      `json:"active_probe"`
	Limitations []string  `json:"limitations"`
}

// RawRecord is the loosely typed PowerShell inventory (python: record).
type RawRecord struct {
	Adapters  []map[string]any `json:"adapters"`
	Neighbors []map[string]any `json:"neighbors"`
}

// pyInt mimics int(x) for JSON numbers, numeric strings and bools.
func pyInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false
		}
		return int(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	}
	return 0, false
}

// pyStr mimics str(x) for the types the inventory produces.
func pyStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case nil:
		return "None", true
	case bool:
		if x {
			return "True", true
		}
		return "False", true
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return strconv.FormatInt(int64(x), 10), true // JSON integers arrive as float64
		}
		return strconv.FormatFloat(x, 'g', -1, 64), true
	}
	return "", false
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func orEmpty(v any) string {
	if !truthy(v) {
		return ""
	}
	s, _ := pyStr(v)
	return s
}

func parse4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, false
	}
	return a, true
}

// Normalize is normalize_inventory. now is the observed_at stamp.
func Normalize(rec RawRecord, now float64) Inventory {
	adapters := []Adapter{}
	for _, row := range rec.Adapters {
		addrS, ok := row["address"].(string)
		if !ok {
			continue
		}
		addr, ok := parse4(addrS)
		if !ok {
			continue
		}
		plen, ok := pyInt(row["prefix_length"])
		if !ok || plen < 0 || plen > 32 {
			continue
		}
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		index, ok := pyInt(row["index"])
		if !ok {
			continue
		}
		rawName, present := row["name"]
		name, ok := pyStr(rawName)
		if !ok || !present {
			continue
		}
		up, present := row["up"]
		if !present {
			continue
		}
		pfx, _ := addr.Prefix(plen)
		dpfx, _ := addr.Prefix(max(24, plen))
		adapters = append(adapters, Adapter{Index: index, Name: name, Address: addr.String(), PrefixLength: plen, Subnet: pfx.String(), DiscoverySubnet: dpfx.String(),
			Up: truthy(up), MAC: orEmpty(row["mac"]), Description: orEmpty(row["description"])})
	}
	type key struct {
		idx  int
		addr string
	}
	byKey := map[key]Device{}
	for _, row := range rec.Neighbors {
		addrS, ok := row["address"].(string)
		if !ok {
			continue
		}
		addr, ok := parse4(addrS)
		if !ok {
			continue
		}
		mac := strings.ToLower(strings.ReplaceAll(orEmpty(row["mac"]), "-", ":"))
		if addr.IsMulticast() || addr.IsUnspecified() || addr.IsLoopback() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			continue
		}
		if mac == "" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		st, present := row["state"]
		if !present {
			continue
		}
		state, ok := pyStr(st)
		if !ok {
			continue
		}
		if l := strings.ToLower(state); l == "incomplete" || l == "unreachable" {
			continue
		}
		idx, ok := pyInt(row["interface_index"])
		if !ok {
			continue
		}
		byKey[key{idx, addr.String()}] = Device{InterfaceIndex: idx, Address: addr.String(), MAC: mac, State: state, Source: "neighbor_cache", ReachableNow: strings.ToLower(state) == "reachable"}
	}
	devices := make([]Device, 0, len(byKey))
	for _, d := range byKey {
		devices = append(devices, d)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].InterfaceIndex != devices[j].InterfaceIndex {
			return devices[i].InterfaceIndex < devices[j].InterfaceIndex
		}
		a, _ := netip.ParseAddr(devices[i].Address)
		b, _ := netip.ParseAddr(devices[j].Address)
		return a.Less(b)
	})
	total := len(devices)
	if len(devices) > 4096 {
		devices = devices[:4096]
	}
	returned := min(128, len(adapters))
	if len(adapters) > 128 {
		adapters = adapters[:128]
	}
	return Inventory{ObservedAt: now, Adapters: adapters, Devices: devices,
		Coverage:    Coverage{AdaptersReturned: returned, DevicesReturned: min(4096, total), AdapterLimitReached: len(rec.Adapters) >= 129, NeighborLimitReached: len(rec.Neighbors) >= 4097},
		Limitations: []string{"Neighbor-cache entries do not prove a device is currently online.", "Hostnames and hardware vendors are not inferred from IP/MAC addresses."}}
}

var privateNetworks = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

func subnetOf(inner, outer netip.Prefix) bool {
	return inner.Bits() >= outer.Bits() && outer.Contains(inner.Addr())
}

// ValidateScan is validate_scan: it returns the source and ordered targets.
func ValidateScan(subnet, source string, interfaceIndex int, adapters []Adapter, maxHosts int) (string, []string, error) {
	if maxHosts < 1 || maxHosts > 256 {
		return "", nil, errors.New("Discovery is limited to 256 addresses")
	}
	network, err := netip.ParsePrefix(subnet)
	if err != nil || !network.Addr().Is4() || network.Masked() != network {
		return "", nil, fmt.Errorf("invalid subnet %q", subnet)
	}
	src, ok := parse4(source)
	if !ok {
		return "", nil, fmt.Errorf("invalid source address %q", source)
	}
	private := false
	for _, p := range privateNetworks {
		if subnetOf(network, p) {
			private = true
		}
	}
	if !private {
		return "", nil, errors.New("Choose an RFC1918 private local subnet")
	}
	var sel *Adapter
	for i := range adapters {
		if adapters[i].Index == interfaceIndex && adapters[i].Address == src.String() && adapters[i].Up {
			sel = &adapters[i]
			break
		}
	}
	if sel == nil {
		return "", nil, errors.New("The selected source address is not on an active adapter")
	}
	local, err := netip.ParsePrefix(sel.Subnet)
	if err != nil {
		return "", nil, err
	}
	if !network.Contains(src) || !subnetOf(network, local) {
		return "", nil, errors.New("Discovery must stay inside the selected adapter subnet")
	}
	size := 1 << (32 - network.Bits())
	if size > maxHosts+2 {
		return "", nil, errors.New("Choose a smaller local subnet (at most 256 addresses)")
	}
	var targets []string
	// network.hosts(): excludes network/broadcast for /30 and wider; /31 and /32 yield all.
	first, last := network.Addr(), lastAddr(network)
	lo, hi := u32(first), u32(last)
	if network.Bits() < 31 {
		lo++
		hi--
	}
	for v := lo; v <= hi && v >= lo; v++ {
		a := fromU32(v)
		if a != src {
			targets = append(targets, a.String())
		}
		if v == math.MaxUint32 {
			break
		}
	}
	if len(targets) > maxHosts {
		return "", nil, errors.New("Too many discovery targets")
	}
	return src.String(), targets, nil
}

func u32(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }
func fromU32(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
func lastAddr(p netip.Prefix) netip.Addr {
	host := uint32(1)<<(32-p.Bits()) - 1
	if p.Bits() == 0 {
		host = math.MaxUint32
	}
	return fromU32(u32(p.Addr()) | host)
}

// Now returns the current Unix time in seconds.
func Now() float64 { return float64(time.Now().UnixNano()) / 1e9 }
