package main

import "syscall"

// tuneProcess requests a 1 ms timer tick and a priority above ordinary desktop work.
func tuneProcess() {
	winmm := syscall.NewLazyDLL("winmm.dll")
	if p := winmm.NewProc("timeBeginPeriod"); p.Find() == nil {
		p.Call(1)
	}
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrent, setClass := k32.NewProc("GetCurrentProcess"), k32.NewProc("SetPriorityClass")
	if h, _, _ := getCurrent.Call(); h != 0 {
		setClass.Call(h, 0x00008000) // ABOVE_NORMAL_PRIORITY_CLASS
	}
}
