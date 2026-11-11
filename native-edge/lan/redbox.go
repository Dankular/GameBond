package lan

import (
	"errors"
	"sync"
	"time"

	"gamebond.local/nativeedge/iec62439"
)

// RedBoxCounters count what the PRP layer did.
type RedBoxCounters struct {
	Sent, Received, DuplicatesDropped, NoRCT, WrongLAN, OwnFramesDropped, SupervisionSent, SupervisionReceived, WriteErrors uint64
}

// RedBox presents two LAN ports (PRP LAN A and LAN B) to the gateway as one FrameIO.
// Frames written go out on both ports with a Redundancy Control Trailer; frames read
// from either port are de-duplicated and have the trailer removed, so the gateway sees
// each frame once even if one LAN is down. Frames without a valid trailer (from singly
// attached nodes) are passed through. Supervision frames are sent every two seconds and
// consumed here; they feed the node table that reports which LAN has gone quiet.
type RedBox struct {
	a, b  FrameIO
	mac   [6]byte
	now   func() time.Time
	in    chan portFrame
	done  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup
	wmu   sync.Mutex
	seq   uint16
	mu    sync.Mutex
	disc  *iec62439.Discard
	nodes *iec62439.Nodes
	sup   iec62439.Supervisor
	c     RedBoxCounters
}

type portFrame struct {
	frame []byte
	lan   uint8
}

// NewRedBox starts reading both ports. Both ports must use the same MAC address, as PRP
// requires; the MAC of port A is used. now may be nil.
func NewRedBox(a, b FrameIO, now func() time.Time) *RedBox {
	if now == nil {
		now = time.Now
	}
	r := &RedBox{a: a, b: b, mac: a.MAC(), now: now, in: make(chan portFrame, 1024), done: make(chan struct{}),
		disc: iec62439.NewDiscard(), nodes: iec62439.NewNodes()}
	r.sup = iec62439.Supervisor{MAC: r.mac}
	r.wg.Add(2)
	go r.pump(a, iec62439.LANA)
	go r.pump(b, iec62439.LANB)
	return r
}

func (r *RedBox) pump(io FrameIO, lan uint8) {
	defer r.wg.Done()
	for {
		select {
		case <-r.done:
			return
		default:
		}
		f, err := io.Read(100 * time.Millisecond)
		if err != nil {
			if errors.Is(err, ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // a failed port must not stop the other
			continue
		}
		if f == nil {
			continue
		}
		select {
		case r.in <- portFrame{f, lan}:
		case <-r.done:
			return
		}
	}
}

func (r *RedBox) MAC() [6]byte { return r.mac }

// Write sends the frame on both LANs. It fails only if both ports fail.
func (r *RedBox) Write(frame []byte) error {
	r.wmu.Lock()
	seq := r.seq
	r.seq++
	r.wmu.Unlock()
	fa, err := iec62439.AppendRCT(frame, seq, iec62439.LANA)
	if err != nil {
		return err
	}
	fb, _ := iec62439.AppendRCT(frame, seq, iec62439.LANB)
	ea, eb := r.a.Write(fa), r.b.Write(fb)
	r.mu.Lock()
	r.c.Sent++
	if ea != nil {
		r.c.WriteErrors++
	}
	if eb != nil {
		r.c.WriteErrors++
	}
	r.mu.Unlock()
	if ea != nil && eb != nil {
		return ea
	}
	return nil
}

// Read returns the next frame for the gateway, sending a supervision frame first when due.
func (r *RedBox) Read(timeout time.Duration) ([]byte, error) {
	r.tick()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case pf := <-r.in:
			if out := r.accept(pf); out != nil {
				return out, nil
			}
		case <-deadline.C:
			return nil, nil
		case <-r.done:
			return nil, ErrClosed
		}
	}
}

func (r *RedBox) tick() {
	now := r.now()
	r.mu.Lock()
	a, b := r.sup.Due(now)
	r.nodes.Forget(now)
	r.mu.Unlock()
	if a == nil {
		return
	}
	ea, eb := r.a.Write(a), r.b.Write(b)
	r.mu.Lock()
	r.c.SupervisionSent++
	if ea != nil || eb != nil {
		r.c.WriteErrors++
	}
	r.mu.Unlock()
}

// accept applies the PRP receive rules to one frame; nil means consumed or dropped.
func (r *RedBox) accept(pf portFrame) []byte {
	f := pf.frame
	if len(f) < 14 {
		return nil
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	var src [6]byte
	copy(src[:], f[6:12])
	if src == r.mac {
		r.c.OwnFramesDropped++
		return nil
	}
	body, rct, ok := iec62439.StripRCT(f)
	if !ok {
		r.c.NoRCT++
		r.c.Received++
		if sup, isSup := iec62439.ParseSupervision(f); isSup {
			r.c.SupervisionReceived++
			r.nodes.Supervision(sup, pf.lan, now)
			return nil
		}
		r.nodes.Observe(src, pf.lan, now)
		return f
	}
	if rct.Lan != pf.lan {
		r.c.WrongLAN++ // wiring error: LAN A traffic arriving on port B or the reverse
	}
	r.nodes.Observe(src, rct.Lan, now)
	if !r.disc.Accept(src, rct.Seq, now) {
		r.c.DuplicatesDropped++
		return nil
	}
	r.c.Received++
	if sup, isSup := iec62439.ParseSupervision(body); isSup {
		r.c.SupervisionReceived++
		r.nodes.Supervision(sup, rct.Lan, now)
		return nil
	}
	return body
}

// Stats returns a snapshot of the counters.
func (r *RedBox) Stats() RedBoxCounters {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.c
}

// LANDown reports which LAN has gone silent for the given peer.
func (r *RedBox) LANDown(peer [6]byte) (a, b bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nodes.LANDown(peer, r.now())
}

// Close stops reading and closes both ports.
func (r *RedBox) Close() error {
	r.once.Do(func() { close(r.done) })
	ea, eb := r.a.Close(), r.b.Close()
	r.wg.Wait()
	if ea != nil {
		return ea
	}
	return eb
}

var _ FrameIO = (*RedBox)(nil)
