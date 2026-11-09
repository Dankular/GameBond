package desktopruntime

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
)

func clientProcessAlive(pid int, expected string) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err != windows.ERROR_INVALID_PARAMETER
	}
	defer windows.CloseHandle(h)
	var exit uint32
	if windows.GetExitCodeProcess(h, &exit) == nil && exit != 259 {
		return false
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return true
	}
	return strings.EqualFold(filepath.Clean(windows.UTF16ToString(buf[:size])), filepath.Clean(expected))
}
