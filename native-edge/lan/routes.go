package lan

import (
	"net/netip"
	"sort"
	"strings"
)

// ResolvedRoute is the selected connected or static route for a destination.
type ResolvedRoute struct {
	Network NetworkConfig
	Prefix  netip.Prefix
	NextHop netip.Addr
	Static  bool
}

// RouteStatus is a user-visible route row.
type RouteStatus struct {
	Destination string `json:"destination"`
	Network     string `json:"network"`
	NextHop     string `json:"next_hop,omitempty"`
	Kind        string `json:"kind"`
}

// RouteTable resolves configured connected and static routes. Connected routes
// take precedence; static routes use longest-prefix match.
type RouteTable struct {
	connected []NetworkConfig
	static    []StaticRoute
}

// NewRouteTable builds an immutable route table from validated config.
func NewRouteTable(config LocalConfig) *RouteTable {
	r := &RouteTable{connected: append([]NetworkConfig(nil), config.Networks...), static: append([]StaticRoute(nil), config.Routes...)}
	sort.Slice(r.static, func(i, j int) bool {
		if r.static[i].Destination.Bits() != r.static[j].Destination.Bits() {
			return r.static[i].Destination.Bits() > r.static[j].Destination.Bits()
		}
		return r.static[i].Destination.String() < r.static[j].Destination.String()
	})
	return r
}

// Lookup returns the connected route or most-specific static route owning dst.
func (r *RouteTable) Lookup(dst netip.Addr) (ResolvedRoute, bool) {
	if r == nil || !dst.Is4() {
		return ResolvedRoute{}, false
	}
	for _, network := range r.connected {
		if network.Prefix.Contains(dst) {
			return ResolvedRoute{Network: network, Prefix: network.Prefix.Masked(), NextHop: dst}, true
		}
	}
	for _, route := range r.static {
		if route.Destination.Contains(dst) {
			for _, network := range r.connected {
				if strings.EqualFold(network.Name, route.Interface) {
					return ResolvedRoute{Network: network, Prefix: route.Destination, NextHop: route.NextHop, Static: true}, true
				}
			}
		}
	}
	return ResolvedRoute{}, false
}

// Routes returns connected and static route rows in deterministic order.
func (r *RouteTable) Routes() []RouteStatus {
	if r == nil {
		return nil
	}
	rows := make([]RouteStatus, 0, len(r.connected)+len(r.static))
	for _, network := range r.connected {
		rows = append(rows, RouteStatus{Destination: network.Prefix.Masked().String(), Network: network.Name, Kind: "connected"})
	}
	for _, route := range r.static {
		rows = append(rows, RouteStatus{Destination: route.Destination.String(), Network: route.Interface, NextHop: route.NextHop.String(), Kind: "static"})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Destination != rows[j].Destination {
			return rows[i].Destination < rows[j].Destination
		}
		return rows[i].Kind < rows[j].Kind
	})
	return rows
}
