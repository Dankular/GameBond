package main

import "runtime/debug"

func init() {
	// Same reasoning as the client: a small heap with a high allocation rate, so collect
	// less often instead of every few milliseconds.
	debug.SetGCPercent(400)
	debug.SetMemoryLimit(1 << 30)
	tuneProcess()
}
