package main

import (
	"errors"

	"gamebond.local/nativeedge/lan"
)

func openFrameIO(d lan.DeviceConfig) (lan.FrameIO, error) {
	if d.InterfaceName == "" {
		return nil, errors.New("lan_devices needs interface_name on Linux")
	}
	return lan.OpenLinux(d.InterfaceName)
}

func openLocalNetworkFrameIO(n lan.NetworkConfig) (lan.FrameIO, error) {
	if n.InterfaceName == "" {
		return nil, errors.New("local network needs interface_name on Linux")
	}
	return lan.OpenLinux(n.InterfaceName)
}
