//go:build !windows

package desktopruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func clientProcessAlive(pid int, expected string) bool {
	if pid <= 0 {
		return false
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return !os.IsNotExist(err)
	}
	return filepath.Clean(strings.TrimSuffix(path, " (deleted)")) == filepath.Clean(expected)
}
