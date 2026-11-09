package tray

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW = kernel32.NewProc("CreateMutexW")
	procCreateEventW = kernel32.NewProc("CreateEventW")
	procSetEvent     = kernel32.NewProc("SetEvent")
	procWaitSingle   = kernel32.NewProc("WaitForSingleObject")
	procCloseHandle  = kernel32.NewProc("CloseHandle")
	errAlreadyExists = syscall.Errno(183)
)

// Lease is one tray agent per workspace (AgentLease): a second launch signals
// the owner's Show event instead of starting another icon.
type Lease struct {
	Owner        bool
	event, mutex uintptr
}

// LeaseName is Local\GameBond.Widget.<first 16 hex of sha256(normcase(root))>.
func LeaseName(root string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(root))))
	return `Local\GameBond.Widget.` + hex.EncodeToString(sum[:])[:16]
}

func AcquireLease(root string) (*Lease, error) {
	name := LeaseName(root)
	n1, _ := syscall.UTF16PtrFromString(name + ".Show")
	ev, _, err := procCreateEventW.Call(0, 0, 0, uintptr(unsafe.Pointer(n1)))
	if ev == 0 {
		return nil, err
	}
	n2, _ := syscall.UTF16PtrFromString(name)
	mu, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(n2)))
	if mu == 0 {
		procCloseHandle.Call(ev)
		return nil, err
	}
	l := &Lease{event: ev, mutex: mu, Owner: err != errAlreadyExists}
	if !l.Owner {
		procSetEvent.Call(ev)
	}
	return l, nil
}

// ShowRequested consumes a pending Show signal from another launch.
func (l *Lease) ShowRequested() bool {
	r, _, _ := procWaitSingle.Call(l.event, 0)
	return r == 0
}

func (l *Lease) Close() {
	for _, h := range []*uintptr{&l.event, &l.mutex} {
		if *h != 0 {
			procCloseHandle.Call(*h)
			*h = 0
		}
	}
}
