//go:build !windows

package dashboard

func discoverUSBNetworkDevices() ([]USBNetworkDevice, error) { return nil, nil }
