package main

import "runtime/debug"

func init() {
	// The packet path allocates a few KB per datagram; a larger GC target means far
	// fewer collections on a heap that is only tens of MB, and the soft limit stops it
	// growing without bound.
	debug.SetGCPercent(400)
	debug.SetMemoryLimit(1 << 30)
	tuneProcess()
}
