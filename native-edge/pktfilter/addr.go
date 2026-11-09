package pktfilter

import "unsafe"

func addressOf(b []byte) uint64 { return uint64(uintptr(unsafe.Pointer(unsafe.SliceData(b)))) }
