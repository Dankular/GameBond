package main

import (
	"errors"

	"gamebond.local/nativeedge/lan"
	"gamebond.local/nativeedge/pktfilter"
)

// openFrameIO attaches to the Windows Packet Filter driver for the device's
// adapter GUID. It puts the adapter in tunnel mode (host traffic toward it is
// discarded), so it is only reached for configured lan_devices.
func openFrameIO(d lan.DeviceConfig) (lan.FrameIO, error) {
	if d.InterfaceID == "" {
		return nil, errors.New("lan_devices needs interface_id on Windows")
	}
	dev, err := pktfilter.OpenDevice()
	if err != nil {
		return nil, err
	}
	a, err := pktfilter.Open(d.InterfaceID, dev)
	if err != nil {
		dev.Close()
		return nil, err
	}
	return a.OwnDriver(), nil
}
