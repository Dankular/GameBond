//go:build windows

package capture

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// KillStale terminates every ProxiFyre.exe running from dir, other than this
// process's own children, and reports how many it ended. Two copies would
// both divert traffic with WinDivert; a stale one points at a dead SOCKS
// endpoint and silently blackholes the apps it captured.
func KillStale(dir string) int {
	want := strings.ToLower(filepath.Join(dir, "ProxiFyre.exe"))
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	killed := 0
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if !strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), "ProxiFyre.exe") {
			continue
		}
		h, oerr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, e.ProcessID)
		if oerr != nil {
			continue
		}
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil && strings.ToLower(windows.UTF16ToString(buf[:n])) == want {
			if windows.TerminateProcess(h, 1) == nil {
				killed++
			}
		}
		windows.CloseHandle(h)
	}
	return killed
}
