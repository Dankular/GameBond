//go:build windows

package hrclock

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procCounter = kernel32.NewProc("QueryPerformanceCounter")
	procFreq    = kernel32.NewProc("QueryPerformanceFrequency")
	frequency   = queryFrequency() // a var initialiser: it must run before baseTick is read
)

func queryFrequency() int64 {
	var f int64
	if r, _, _ := procFreq.Call(uintptr(unsafe.Pointer(&f))); r != 0 && f > 0 {
		return f
	}
	return 0
}

func ticks() int64 {
	var c int64
	if frequency == 0 {
		return time.Now().UnixNano()
	}
	procCounter.Call(uintptr(unsafe.Pointer(&c)))
	return c
}

func elapsed(base int64) time.Duration {
	now := ticks()
	if frequency == 0 {
		return time.Duration(now - base)
	}
	d := now - base
	// Split to avoid overflow of d * 1e9 on long uptimes.
	return time.Duration(d/frequency)*time.Second + time.Duration(d%frequency)*time.Second/time.Duration(frequency)
}
