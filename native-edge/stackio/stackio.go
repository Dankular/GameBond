// Package stackio speaks the framing between the client runtime and the Go
// netstack helper (`netstack --proxy-stdio`): each frame is
//
//	kind u8 | size u16 big-endian | payload
//
// kind 0 is one IPv4 packet (at most 1280 bytes), kind 2 is control JSON from
// the stack (readiness, app metrics, authorization requests), and kind 3 is
// control JSON to the stack. This matches gamebond/userspace.py.
package stackio

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	KindPacket      = 0
	KindStackEvent  = 2 // stack -> runtime JSON
	KindStackAnswer = 3 // runtime -> stack JSON
	MaxPacket       = 1280
	MaxFrame        = 65535
)

var ErrFrame = errors.New("stackio: invalid frame")

type Frame struct {
	Kind    byte
	Payload []byte
}

// Read returns the next frame. A zero size, or a packet over MaxPacket, is a
// protocol violation exactly as in the Python reader.
func Read(r io.Reader) (Frame, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Frame{}, err
	}
	size := int(binary.BigEndian.Uint16(head[1:]))
	if size == 0 || (head[0] == KindPacket && size > MaxPacket) {
		return Frame{}, ErrFrame
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{head[0], payload}, nil
}

// Writer serialises frames from several goroutines onto one stream.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
	// Timing of the writes, to tell a busy lock (other writers) from a slow pipe (the
	// reader is not draining): worst case in nanoseconds and counts over 10 ms.
	lockMax, writeMax, lockOver10, writeOver10, writes atomic.Int64
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (w *Writer) Write(kind byte, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxFrame || (kind == KindPacket && len(payload) > MaxPacket) {
		return ErrFrame
	}
	buf := make([]byte, 3+len(payload))
	buf[0] = kind
	binary.BigEndian.PutUint16(buf[1:], uint16(len(payload)))
	copy(buf[3:], payload)
	t0 := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	t1 := time.Now()
	_, err := w.w.Write(buf)
	t2 := time.Now()
	w.writes.Add(1)
	noteMax(&w.lockMax, &w.lockOver10, t1.Sub(t0))
	noteMax(&w.writeMax, &w.writeOver10, t2.Sub(t1))
	return err
}

func noteMax(max, over10 *atomic.Int64, d time.Duration) {
	if d > 10*time.Millisecond {
		over10.Add(1)
	}
	for {
		cur := max.Load()
		if int64(d) <= cur || max.CompareAndSwap(cur, int64(d)) {
			return
		}
	}
}

// Timing reports the write timings: how long a call waited for the lock and how long
// the pipe write itself took.
func (w *Writer) Timing() map[string]any {
	ms := func(v int64) float64 { return float64(v) / 1e6 }
	return map[string]any{"writes": w.writes.Load(), "lock_wait_max_ms": ms(w.lockMax.Load()), "lock_wait_over_10ms": w.lockOver10.Load(),
		"pipe_write_max_ms": ms(w.writeMax.Load()), "pipe_write_over_10ms": w.writeOver10.Load()}
}
