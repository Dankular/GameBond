package pktfilter

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW     = kernel32.NewProc("CreateFileW")
	procDeviceIoControl = kernel32.NewProc("DeviceIoControl")
	procGetOverlapped   = kernel32.NewProc("GetOverlappedResult")
	procCreateEventW    = kernel32.NewProc("CreateEventW")
	procWaitSingle      = kernel32.NewProc("WaitForSingleObject")
	procResetEvent      = kernel32.NewProc("ResetEvent")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
)

const (
	errorIoPending     = 997
	fileFlagOverlapped = 0x40000000
	invalidHandle      = ^uintptr(0)
	waitObject0        = 0
	waitFailed         = 0xFFFFFFFF
	genericNone        = 0
	shareReadWrite     = 3
	openExisting       = 3
)

type overlapped struct {
	Internal, InternalHigh uintptr
	Offset, OffsetHigh     uint32
	Event                  uintptr
}

// Device is the real \.\NDISRD handle.
type Device struct {
	handle uintptr
	events sync.Pool // per-call completion events for synchronous IOCTLs
}

// OpenDevice opens the installed Windows Packet Filter driver.
func OpenDevice() (*Device, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, errors.New("LAN devices need a 64-bit build (the driver structures are 64-bit)")
	}
	path, _ := syscall.UTF16PtrFromString(DevicePath)
	h, _, e := procCreateFileW.Call(uintptr(unsafe.Pointer(path)), genericNone, shareReadWrite, 0, openExisting, fileFlagOverlapped, 0)
	if h == 0 || h == invalidHandle {
		return nil, fmt.Errorf("Windows Packet Filter driver is not available: %w", e)
	}
	d := &Device{handle: h}
	d.events.New = func() any {
		ev, _, _ := procCreateEventW.Call(0, 1, 0, 0)
		return ev
	}
	return d, nil
}

// Ioctl is a synchronous IOCTL on an overlapped handle.
func (d *Device) Ioctl(code uint32, in, out []byte) (bool, int) {
	ev := d.events.Get().(uintptr)
	if ev == 0 {
		return false, 0
	}
	defer d.events.Put(ev)
	ov := overlapped{Event: ev}
	var returned uint32
	var inP, outP uintptr
	if len(in) > 0 {
		inP = uintptr(unsafe.Pointer(&in[0]))
	}
	if len(out) > 0 {
		outP = uintptr(unsafe.Pointer(&out[0]))
	}
	r, _, e := procDeviceIoControl.Call(d.handle, uintptr(code), inP, uintptr(len(in)), outP, uintptr(len(out)),
		uintptr(unsafe.Pointer(&returned)), uintptr(unsafe.Pointer(&ov)))
	if r == 0 {
		if en, ok := e.(syscall.Errno); !ok || en != errorIoPending {
			runtime.KeepAlive(in)
			runtime.KeepAlive(out)
			return false, 0
		}
		returned = 0
		r, _, _ = procGetOverlapped.Call(d.handle, uintptr(unsafe.Pointer(&ov)), uintptr(unsafe.Pointer(&returned)), 1)
	}
	runtime.KeepAlive(in)
	runtime.KeepAlive(out)
	runtime.KeepAlive(&ov)
	return r != 0, int(returned)
}

func (d *Device) CreateEvent() (uintptr, error) {
	ev, _, e := procCreateEventW.Call(0, 1, 0, 0)
	if ev == 0 {
		return 0, e
	}
	return ev, nil
}

func (d *Device) Wait(event uintptr, t time.Duration) (bool, error) {
	r, _, e := procWaitSingle.Call(event, uintptr(t/time.Millisecond))
	if uint32(r) == waitFailed {
		return false, e
	}
	return r == waitObject0, nil
}

func (d *Device) ResetEvent(event uintptr) { procResetEvent.Call(event) }
func (d *Device) CloseEvent(event uintptr) { procCloseHandle.Call(event) }

func (d *Device) Close() error {
	procCloseHandle.Call(d.handle)
	return nil
}
