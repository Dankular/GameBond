//go:build !windows

package atomicio

import (
	"os"
	"time"
)

func openShared(path string) (*os.File, error) { return os.Open(path) }

// ReplaceFile is an atomic rename on POSIX systems.
func ReplaceFile(src, dst string, _ time.Duration) error { return os.Rename(src, dst) }
