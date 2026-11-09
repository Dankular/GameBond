//go:build linux

package uplink

import "golang.org/x/sys/unix"

// IP_MTU_DISCOVER = IP_PMTUDISC_DO, as Python's _enable_df.
func setDF(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
}
func getDF(fd uintptr) bool {
	v, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	return err == nil && v == unix.IP_PMTUDISC_DO
}
