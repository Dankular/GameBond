//go:build linux

package uplink

import "golang.org/x/sys/unix"

func pin(fd uintptr, _ int, name string) error {
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
}

func setBuffers(fd uintptr, n int) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, n); err != nil {
		return err
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, n)
}
