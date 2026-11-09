// Package router is the Go port of gamebond/transport_router.py: it runs the
// GameBond tunnel and an OpenMPTCProuter (OMR) tunnel behind one sender. Game
// and call traffic (by DSCP) uses GameBond; everything else uses OMR through a
// source NAT. A flow stays on one transport and is re-decided if that
// transport stops being ready.
package router

import (
	"container/list"
	"sync"
	"time"

	"gamebond.local/nativeedge/nat"
)

const (
	GameBond  = "gamebond"
	OMR       = "omr"
	FlowCache = 16384
)

// DefaultGameBondDSCP are the classes sent over GameBond (gameplay 46, calls 26).
var DefaultGameBondDSCP = []int{46, 26}

// GameBondTransport is the GameBond side.
type GameBondTransport interface {
	Send(payload []byte, replicate bool, flowID string, urgent bool) bool
	Ready() bool // any healthy, enabled path
}

// OMRTransport is the OMR side.
type OMRTransport interface {
	Send(packet []byte, urgent bool) bool
	Ready() bool
}

// Counters mirror the Python names.
type Counters struct {
	SentGameBond, SentOMR, Fallbacks, NATDropped, SendFailed uint64
	RecvGameBond, RecvOMR, RecvNATDropped, InboxFull         uint64
}

type flow struct {
	transport string
	seen      time.Time
	elem      *list.Element
	id        string
}

type readyStamp struct {
	at    time.Time
	value bool
}

// Router chooses a transport per flow.
type Router struct {
	mu       sync.Mutex
	gb       GameBondTransport
	omr      OMRTransport
	nat      *nat.Nat
	dscp     map[int]bool
	flowTTL  time.Duration
	readyTTL time.Duration
	Now      func() time.Time
	flows    map[string]*flow
	order    *list.List
	ready    map[string]readyStamp
	c        Counters
	inbox    chan []byte
}

// New builds a router; a nil dscp uses DefaultGameBondDSCP.
func New(gb GameBondTransport, omr OMRTransport, n *nat.Nat, dscp []int, flowTTL, readyTTL time.Duration) *Router {
	if dscp == nil {
		dscp = DefaultGameBondDSCP
	}
	if flowTTL == 0 {
		flowTTL = 120 * time.Second
	}
	if readyTTL == 0 {
		readyTTL = 250 * time.Millisecond
	}
	r := &Router{gb: gb, omr: omr, nat: n, dscp: map[int]bool{}, flowTTL: flowTTL, readyTTL: readyTTL, Now: time.Now,
		flows: map[string]*flow{}, order: list.New(), ready: map[string]readyStamp{}, inbox: make(chan []byte, 8192)}
	for _, d := range dscp {
		r.dscp[d] = true
	}
	return r
}

func (r *Router) isReady(name string, now time.Time) bool {
	if s, ok := r.ready[name]; ok && now.Sub(s.at) < r.readyTTL {
		return s.value
	}
	var v bool
	if name == OMR {
		v = r.omr.Ready()
	} else {
		v = r.gb.Ready()
	}
	r.ready[name] = readyStamp{now, v}
	return v
}

// Choose picks the transport for a flow (empty flowID is an unkeyed packet).
func (r *Router) Choose(flowID string, dscp int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.choose(flowID, dscp)
}

func (r *Router) choose(flowID string, dscp int) string {
	want := OMR
	if r.dscp[dscp] {
		want = GameBond
	}
	now := r.Now()
	if flowID != "" {
		if f, ok := r.flows[flowID]; ok && now.Sub(f.seen) < r.flowTTL && r.isReady(f.transport, now) {
			f.seen = now
			r.order.MoveToBack(f.elem)
			return f.transport
		}
	}
	if !r.isReady(want, now) {
		other := OMR
		if want == OMR {
			other = GameBond
		}
		if r.isReady(other, now) {
			want = other
			r.c.Fallbacks++
		}
	}
	if flowID != "" {
		if f, ok := r.flows[flowID]; ok {
			f.transport, f.seen = want, now
			r.order.MoveToBack(f.elem)
		} else {
			f := &flow{transport: want, seen: now, id: flowID}
			f.elem = r.order.PushBack(f)
			r.flows[flowID] = f
		}
		for r.order.Len() > FlowCache {
			front := r.order.Front()
			delete(r.flows, front.Value.(*flow).id)
			r.order.Remove(front)
		}
	}
	return want
}

// Send sends one IPv4 packet and returns the number of copies handed to a
// transport (0 if dropped).
func (r *Router) Send(payload []byte, replicate bool, flowID string, urgent bool, dscp int) int {
	r.mu.Lock()
	target := r.choose(flowID, dscp)
	r.mu.Unlock()
	if target == OMR {
		translated := r.nat.Outbound(payload)
		r.mu.Lock()
		defer r.mu.Unlock()
		if translated == nil {
			r.c.NATDropped++
			return 0
		}
		if r.omr.Send(translated, urgent || r.dscp[dscp]) {
			r.c.SentOMR++
			return 1
		}
		r.c.SendFailed++
		return 0
	}
	ok := r.gb.Send(payload, replicate, flowID, urgent)
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		r.c.SentGameBond++
		return 1
	}
	r.c.SendFailed++
	return 0
}

// Receive merges an inbound packet from a transport into the inbox; OMR
// packets pass back through the NAT.
func (r *Router) Receive(name string, packet []byte) {
	if name == OMR {
		packet = r.nat.Inbound(packet)
		if packet == nil {
			r.mu.Lock()
			r.c.RecvNATDropped++
			r.mu.Unlock()
			return
		}
	}
	r.mu.Lock()
	if name == OMR {
		r.c.RecvOMR++
	} else {
		r.c.RecvGameBond++
	}
	r.mu.Unlock()
	select {
	case r.inbox <- packet:
	default:
		r.mu.Lock()
		r.c.InboxFull++
		r.mu.Unlock()
	}
}

// Inbox delivers merged inbound packets.
func (r *Router) Inbox() <-chan []byte { return r.inbox }

// Stats returns the counters and the number of tracked flows.
func (r *Router) Stats() (Counters, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.c, len(r.flows)
}
