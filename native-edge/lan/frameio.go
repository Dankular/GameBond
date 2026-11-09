package lan

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrClosed is returned by a closed adapter.
var ErrClosed = errors.New("adapter closed")

// FrameIO is raw Ethernet frame access for a device-facing adapter. Read
// returns only frames received from the wire (nil, nil on timeout), never
// frames this process transmitted.
type FrameIO interface {
	IO
	Read(timeout time.Duration) ([]byte, error)
	Close() error
}

// MemoryIO is an in-process endpoint for tests: frames written appear on the peer.
type MemoryIO struct {
	mac    [6]byte
	inbox  chan []byte
	mu     sync.Mutex
	peer   *MemoryIO
	sent   [][]byte
	closed bool
}

// MemoryPair returns two connected endpoints.
func MemoryPair(a, b [6]byte) (*MemoryIO, *MemoryIO) {
	x := &MemoryIO{mac: a, inbox: make(chan []byte, 1024)}
	y := &MemoryIO{mac: b, inbox: make(chan []byte, 1024)}
	x.peer, y.peer = y, x
	return x, y
}

func (m *MemoryIO) MAC() [6]byte { return m.mac }

func (m *MemoryIO) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *MemoryIO) Read(timeout time.Duration) ([]byte, error) {
	if m.isClosed() {
		return nil, ErrClosed
	}
	select {
	case f := <-m.inbox:
		return f, nil
	case <-time.After(timeout):
		return nil, nil
	}
}

func (m *MemoryIO) Write(frame []byte) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	f := append([]byte(nil), frame...)
	m.sent = append(m.sent, f)
	peer := m.peer
	m.mu.Unlock()
	if peer != nil {
		select {
		case peer.inbox <- f:
		default:
		}
	}
	return nil
}

func (m *MemoryIO) Sent() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.sent...)
}

func (m *MemoryIO) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

// Run reads frames from io into the gateway until ctx ends or the adapter
// fails; the adapter error is returned (nil on a clean stop).
func (g *Gateway) Run(ctx context.Context, io FrameIO) error {
	for ctx.Err() == nil {
		f, err := io.Read(250 * time.Millisecond)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if f != nil {
			g.HandleFrame(f)
		}
	}
	return nil
}
