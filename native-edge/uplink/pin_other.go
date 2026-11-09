//go:build !windows && !linux

package uplink

func pin(uintptr, int, string) error { return ErrUnsupported }
func setBuffers(uintptr, int) error  { return nil }
