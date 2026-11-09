//go:build !linux

package main

import "gamebond.local/nativeedge/lan"

// The Windows frame I/O (packet filter) is not ported yet; the manager reports
// every device as unavailable instead of failing the tunnel.
func openFrameIO(lan.DeviceConfig) (lan.FrameIO, error) { return nil, errNoFrameIO }
