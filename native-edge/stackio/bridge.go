package stackio

import (
	"encoding/json"
	"io"
	"sync/atomic"
	"time"
)

// Uplink is the part of client.Client the bridge needs.
type Uplink interface {
	Send(payload []byte, flow string, ttl time.Duration) bool
}

// Bridge joins the netstack helper's stdio to the bonded client: packets from
// the stack go out through Send, delivered packets are framed back into the
// stack, and control JSON is handed to OnEvent.
type Bridge struct {
	Out     *Writer // to the stack's stdin
	Uplink  Uplink
	TTL     time.Duration // queue lifetime for outbound packets (default 10s)
	OnEvent func(map[string]any)

	Outbound, Injected, Dropped, Malformed atomic.Uint64
}

// Deliver is the client's Deliver callback: it never blocks beyond one write.
func (b *Bridge) Deliver(packet []byte) {
	if len(packet) == 0 || len(packet) > MaxPacket {
		b.Malformed.Add(1)
		return
	}
	if b.Out.Write(KindPacket, packet) == nil {
		b.Injected.Add(1)
	} else {
		b.Dropped.Add(1)
	}
}

// Respond sends a control JSON answer (kind 3) to the stack.
func (b *Bridge) Respond(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Out.Write(KindStackAnswer, raw)
}

// Pump reads the stack's output until it ends. A protocol violation is fatal,
// as in the Python runtime.
func (b *Bridge) Pump(stackOut io.Reader) error {
	ttl := b.TTL
	if ttl == 0 {
		ttl = 10 * time.Second
	}
	for {
		f, err := Read(stackOut)
		if err != nil {
			return err
		}
		switch f.Kind {
		case KindPacket:
			if b.Uplink.Send(f.Payload, "stack", ttl) {
				b.Outbound.Add(1)
			} else {
				b.Dropped.Add(1)
			}
		case KindStackEvent:
			var record map[string]any
			if json.Unmarshal(f.Payload, &record) != nil {
				b.Malformed.Add(1)
				continue
			}
			if b.OnEvent != nil {
				b.OnEvent(record)
			}
		default:
			return ErrFrame
		}
	}
}
