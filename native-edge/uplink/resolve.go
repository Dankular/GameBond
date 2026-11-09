package uplink

import (
	"fmt"
	"net"
	"net/netip"
)

// InterfaceFor finds the adapter that owns addr, so a configuration that lists
// only local addresses can still pin each uplink to its own adapter. It reports
// an error if no adapter owns the address or if several do.
func InterfaceFor(addr netip.Addr) (index int, name string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, "", err
	}
	found := 0
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == addr {
					index, name = ifc.Index, ifc.Name
					found++
				}
			}
		}
	}
	switch found {
	case 0:
		return 0, "", fmt.Errorf("uplink: no adapter owns %s", addr)
	case 1:
		return index, name, nil
	}
	return 0, "", fmt.Errorf("uplink: %s is assigned to %d adapters", addr, found)
}
