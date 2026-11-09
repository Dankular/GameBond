package uplink

import "net/netip"

type defaultRoute struct {
	Index   int
	Gateway string
	Metric  uint32
}

// Each uplink needs its own lowest-cost default route, rather than the first
// gateway in GetAdaptersAddresses. Interface metric is constant within one
// adapter, so it cannot change this per-adapter ranking.
func chooseDefaultGateways(routes []defaultRoute) map[int]defaultRoute {
	chosen := map[int]defaultRoute{}
	for _, route := range routes {
		ip, err := netip.ParseAddr(route.Gateway)
		if err != nil || route.Index <= 0 || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			continue
		}
		old, exists := chosen[route.Index]
		previous, _ := netip.ParseAddr(old.Gateway)
		if !exists || route.Metric < old.Metric || (route.Metric == old.Metric && ip.Compare(previous) < 0) {
			chosen[route.Index] = route
		}
	}
	return chosen
}
