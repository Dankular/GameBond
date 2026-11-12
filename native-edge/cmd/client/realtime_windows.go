package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// tuneProcess asks Windows for a 1 ms timer tick (the default is 15.6 ms, which is the
// size of the stalls and clumps a sleeping loop produces) and a priority above
// ordinary desktop work, so another process cannot hold the packet loop off a core.
func tuneProcess() {
	if winmm := syscall.NewLazyDLL("winmm.dll"); winmm.NewProc("timeBeginPeriod").Find() == nil {
		winmm.NewProc("timeBeginPeriod").Call(1)
	}
	windows.SetPriorityClass(windows.CurrentProcess(), windows.ABOVE_NORMAL_PRIORITY_CLASS)
}
