package dashboard

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func discoverAdapters() ([]Adapter, error) {
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
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				ip := g.Address.IP()
				if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
					row.Gateway = ip.String()
					break
				}
			}
			rows = append(rows, row)
		}
		runtime.KeepAlive(buf)
		return rows, nil
	}
	return nil, errors.New("adapter discovery changed repeatedly; refresh the networks")
}
