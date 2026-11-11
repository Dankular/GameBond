//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var getUdpStatistics = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetUdpStatistics")

// mibUDPStats is MIB_UDPSTATS.
type mibUDPStats struct {
	InDatagrams, NoPorts, InErrors, OutDatagrams, NumAddrs uint32
}

// osUDPReceiveErrors is the system-wide count of UDP datagrams Windows received but
// could not hand to a socket (a full receive buffer is the usual cause). It rises when
// loss happens inside this machine, where no redundancy on the wire can help.
func osUDPReceiveErrors() (uint64, bool) {
	var s mibUDPStats
	r, _, _ := getUdpStatistics.Call(uintptr(unsafe.Pointer(&s)))
	if r != 0 {
		return 0, false
	}
	return uint64(s.InErrors), true
}
