//go:build windows

package appauth

import (
	"math"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"gamebond.local/nativeedge/apppolicy"
)

const filetimeUnixEpoch = 116444736000000000

// ResolveProcess is app_events.resolve_process: bind a captured PID
// generation (pid + creation FILETIME) to the live executable, or nil.
func ResolveProcess(pid int64, createdFiletime string) map[string]any {
	if pid <= 0 || pid > math.MaxUint32 {
		return nil
	}
	birth, err := parsePyInt(createdFiletime)
	if err != nil || birth <= filetimeUnixEpoch {
		return nil
	}
	expected := float64(birth-filetimeUnixEpoch) / 10_000_000
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return nil
	}
	actual := float64(created.Nanoseconds()) / 1e9
	if math.Abs(actual-expected) > .001 {
		return nil
	}
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil || n == 0 {
		return nil
	}
	path := windows.UTF16ToString(buf[:n])
	if len(path) > 32768 || !apppolicy.IsAbs(path) {
		return nil
	}
	norm := apppolicy.NormPath(path)
	name := norm[strings.LastIndexByte(norm, '\\')+1:]
	return map[string]any{"pid": pid, "created_at": actual, "created_filetime": strconv.FormatInt(birth, 10),
		"path": norm, "name": name}
}
