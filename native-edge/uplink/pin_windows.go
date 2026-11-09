//go:build windows

package uplink

import (
	"math/bits"
	"syscall"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF takes the interface index in network byte order for IPv4.
func pin(fd uintptr, index int, _ string) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(uint32(index))))
}

func setBuffers(fd uintptr, n int) error {
	h := syscall.Handle(fd)
	if err := syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_RCVBUF, n); err != nil {
		return err
	}
	return syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_SNDBUF, n)
}
