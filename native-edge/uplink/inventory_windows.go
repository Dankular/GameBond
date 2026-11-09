package uplink

import (
	"errors"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Adapters() ([]Adapter, error) {
	gateways, err := windowsDefaultGateways()
	if err != nil {
		return nil, err
	}
	size := uint32(15000)
	for attempt := 0; attempt < 5; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return []Adapter{}, nil
		}
		if err != nil {
			return nil, err
		}
		rows := []Adapter{}
		for a := first; a != nil; a = a.Next {
			if a.IfIndex == 0 || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == windows.IF_TYPE_TUNNEL {
				continue
			}
			id := windows.BytePtrToString(a.AdapterName)
			row := Adapter{Index: int(a.IfIndex), ID: id, Name: windows.UTF16PtrToString(a.FriendlyName), Up: a.OperStatus == 1, Addresses: []string{}}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				ip := u.Address.IP()
				if ip != nil && ip.To4() != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && u.DadState == windows.IpDadStatePreferred {
					row.Addresses = append(row.Addresses, ip.String())
				}
			}
			if route, ok := gateways[row.Index]; ok {
				row.Gateway = route.Gateway
				cost := uint64(route.Metric) + uint64(a.Ipv4Metric)
				row.GatewayMetric = &cost
			}
			rows = append(rows, row)
		}
		runtime.KeepAlive(buf)
		return rows, nil
	}
	return nil, errors.New("adapter discovery changed repeatedly; refresh the networks")
}

func windowsDefaultGateways() (map[int]defaultRoute, error) {
	// Read only. Route preference is route offset + interface metric:
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, errors.New("Windows returned no route table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	routes := []defaultRoute{}
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 || row.ValidLifetime == 0 || row.Loopback != 0 || row.NextHop.Family != windows.AF_INET {
			continue
		}
		prefix := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
		if prefix.Addr != [4]byte{} {
			continue
		}
		next := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop))
		routes = append(routes, defaultRoute{Index: int(row.InterfaceIndex), Gateway: netip.AddrFrom4(next.Addr).String(), Metric: row.Metric})
	}
	return chooseDefaultGateways(routes), nil
}
