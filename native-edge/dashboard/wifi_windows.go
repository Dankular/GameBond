//go:build windows

package dashboard

import (
	"os/exec"
	"syscall"
)

// SampleWiFi runs netsh without flashing a console window.
func SampleWiFi() []WiFiInfo {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return ParseNetshWLAN(string(out))
}
