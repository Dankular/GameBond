// Package hrclock provides a precise Now for pacing. On Windows the Go runtime's
// time.Now advances only about once per millisecond, so a pacer that reads it
// sees time standing still between ticks and can release only its burst
// allowance per tick, which capped bonded sends near 60 Mbit/s. Now here is
// anchored once to the wall clock and then advanced by the performance counter,
// which has sub-microsecond resolution.
package hrclock

import "time"

var (
	baseWall = time.Now()
	baseTick = ticks()
)

// Now returns the current time with sub-microsecond resolution and a monotonic
// reading, so differences between values are exact.
func Now() time.Time { return baseWall.Add(elapsed(baseTick)) }
