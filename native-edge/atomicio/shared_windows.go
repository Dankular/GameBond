package atomicio

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

var replaceFileW = syscall.NewLazyDLL("kernel32.dll").NewProc("ReplaceFileW")

// replaceOnce uses ReplaceFileW (which tolerates readers that share DELETE),
// falling back to a rename when the destination does not exist yet.
func replaceOnce(src, dst string) syscall.Errno {
	if _, err := os.Stat(dst); err == nil {
		s, e1 := syscall.UTF16PtrFromString(src)
		d, e2 := syscall.UTF16PtrFromString(dst)
		if e1 != nil || e2 != nil {
			return syscall.Errno(87)
		}
		r, _, e := replaceFileW.Call(uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(s)), 0, 0, 0, 0)
		if r != 0 {
			return 0
		}
		en, _ := e.(syscall.Errno)
		if en != syscall.Errno(2) {
			return en
		}
	}
	if err := os.Rename(src, dst); err != nil {
		if le, ok := err.(*os.LinkError); ok {
			if en, ok := le.Err.(syscall.Errno); ok {
				return en
			}
		}
		return syscall.EINVAL
	}
	return 0
}

const errSharing, errLock, errAccess = 32, 33, 5

func openShared(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var h syscall.Handle
	// A writer mid-replace can briefly hold the file exclusively; retry that.
	for deadline := time.Now().Add(time.Second); ; {
		h, err = syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
		if en, _ := err.(syscall.Errno); err != nil && (en == errSharing || en == errLock) && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		break
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// ReplaceFile moves src over dst, retrying briefly on sharing violations
// (timeout <= 0 means 1.5 s, as in Python).
func ReplaceFile(src, dst string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	delay := 5 * time.Millisecond
	for {
		en := replaceOnce(src, dst)
		if en == 0 {
			return nil
		}
		if (en != errSharing && en != errLock && en != errAccess) || time.Now().After(deadline) {
			return &os.LinkError{Op: "replace", Old: src, New: dst, Err: en}
		}
		time.Sleep(min(delay, max(0, time.Until(deadline))))
		delay = min(50*time.Millisecond, delay*2)
	}
}
