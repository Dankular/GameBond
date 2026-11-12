package main

import "sync/atomic"

// healthSink receives driver, adapter and capture-process state changes once the client
// exists (the capture supervisor starts earlier). Notes must stay under 16 bytes: the
// durable outage log stores them in a fixed field.
var healthSink atomic.Pointer[func(source string, ok bool, note string)]

func reportHealth(source string, ok bool, note string) {
	if f := healthSink.Load(); f != nil {
		(*f)(source, ok, note)
	}
}
