//go:build !windows && !linux

package uplink

func setDF(uintptr) error { return ErrUnsupported }
func getDF(uintptr) bool  { return false }
