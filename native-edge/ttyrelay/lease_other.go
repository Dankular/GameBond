//go:build !windows

package ttyrelay

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func lockMetadata(path string) (io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrMetadataInUse
	}
	return f, nil
}
