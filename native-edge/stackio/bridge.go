package stackio

import (
	"bytes"
	"encoding/json"
	"gamebond.local/nativeedge/bond"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Uplink is the part of client.Client the bridge needs.
type Uplink interface {
	Submit(bond.QueuedPacket) bool
}

// Bridge joins the netstack helper's stdio to the bonded client: packets from
// the stack go out through Send, delivered packets are framed back into the
// stack, and control JSON is handed to OnEvent.
type Bridge struct {
	Out     *Writer // to the stack's stdin
	Uplink  Uplink
	TTL     time.Duration // queue lifetime for outbound packets (default 10s)
	OnEvent func(map[string]any)
	// Classifier and GamePorts are optional. With a classifier each outbound
	// packet is marked (game UDP ports get DSCP 46), classified, and queued with
	// its priority, replication, tag and the policy's maximum age.
	Classifier *bond.Classifier
	GamePorts  map[uint16]bool
	// Profiles (with ClientIP, the client_tunnel_ip) holds the per-flow
	// profiles applications chose; app_flow_profile records feed it.
	Profiles *bond.FlowProfiles
	ClientIP string

	// outMu serialises outbound: the stack pump and every attached LAN device
	// call it from their own goroutines, and the classifier and profile caches
	// are plain maps.
	outMu sync.Mutex

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
			if b.Uplink.Submit(b.outbound(f.Payload, ttl)) {
				b.Outbound.Add(1)
			} else {
				b.Dropped.Add(1)
			}
		case KindStackEvent:
			var record map[string]any
			// UseNumber keeps Python's int/float distinction (type(pid) is int).
			dec := json.NewDecoder(bytes.NewReader(f.Payload))
			dec.UseNumber()
			if dec.Decode(&record) != nil || dec.More() {
				b.Malformed.Add(1)
				continue
			}
			if record["type"] == "app_flow_profile" && b.Profiles != nil {
				b.Profiles.Observe(record, b.ClientIP, time.Now())
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

// Send marks, classifies and queues a packet that did not come from the stack
// (an attached LAN device); it reports whether the uplink accepted it.
func (b *Bridge) Send(packet []byte) bool {
	ttl := b.TTL
	if ttl == 0 {
		ttl = 10 * time.Second
	}
	if b.Uplink.Submit(b.outbound(packet, ttl)) {
		b.Outbound.Add(1)
		return true
	}
	b.Dropped.Add(1)
	return false
}

// outbound turns a packet from the stack into a queue entry. Packets that do
// not parse as IPv4 are still sent as bulk, as the Python runtime does when
// classification raises.
func (b *Bridge) outbound(packet []byte, ttl time.Duration) bond.QueuedPacket {
	b.outMu.Lock()
	defer b.outMu.Unlock()
	q := bond.QueuedPacket{Payload: packet, Flow: "stack", Expires: time.Now().Add(ttl)}
	if b.Classifier == nil {
		return q
	}
	if marked, err := bond.MarkGameUDP(packet, b.GamePorts); err == nil {
		q.Payload = marked
	}
	info, err := bond.ParseIPv4(q.Payload)
	if err != nil {
		return q
	}
	now := time.Now()
	c := b.Classifier.Classify(info, now)
	if b.Profiles != nil && info.Flow != "" {
		profile := b.Profiles.Lookup(info.Flow, now)
		c = b.Classifier.ForProfile(c, profile)
		if profile != "" && b.Classifier.QoSEnabled() {
			if marked, err := bond.MarkDSCP(q.Payload, c.Tag); err == nil {
				q.Payload = marked
			}
		}
	}
	q.Priority, q.Replicate, q.Tag = c.Policy.Priority, c.Policy.Replicate, c.Tag
	q.ClassCapacity = c.Policy.Capacity
	if c.Policy.MaxAgeMS > 0 {
		q.Expires = time.Now().Add(time.Duration(c.Policy.MaxAgeMS * float64(time.Millisecond)))
	}
	if info.Flow != "" {
		q.Flow = info.Flow
	}
	return q
}
