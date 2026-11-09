package ttyrelay

import (
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
)

func lockMetadata(path string) (io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		f.Close()
		if err == windows.ERROR_LOCK_VIOLATION {
			return nil, ErrMetadataInUse
		}
		return nil, err
	}
	return f, nil // Closing the handle releases the lease even after a crash.
}
