//go:build windows

package uplink

import "golang.org/x/sys/windows"

// IP_DONTFRAGMENT (14), as Python's _enable_df.
func setDF(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 14, 1)
}
func getDF(fd uintptr) bool {
	v, err := windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 14)
	return err == nil && v != 0
}
