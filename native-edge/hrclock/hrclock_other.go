//go:build !windows

package hrclock

import "time"

func ticks() int64 { return time.Now().UnixNano() }

func elapsed(base int64) time.Duration { return time.Duration(time.Now().UnixNano() - base) }
