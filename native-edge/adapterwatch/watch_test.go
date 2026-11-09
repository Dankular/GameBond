package adapterwatch

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gamebond.local/nativeedge/uplink"
)

var (
	a = netip.MustParseAddr("192.168.1.10")
	b = netip.MustParseAddr("10.0.0.5")
)

type world struct {
	mu sync.Mutex
	m  map[netip.Addr]int
}

func (w *world) set(addr netip.Addr, idx int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if idx == 0 {
		delete(w.m, addr)
	} else {
		w.m[addr] = idx
	}
}

func (w *world) lookup(addr netip.Addr) (int, string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if idx, ok := w.m[addr]; ok {
		return idx, "x", nil
	}
	return 0, "", errors.New("no adapter")
}

func TestPlan(t *testing.T) {
	w := &world{m: map[netip.Addr]int{a: 11, b: 12}}
	slots := []Slot{{Spec: uplink.Spec{Addr: a, InterfaceIndex: 11}, Pinned: true}, {Spec: uplink.Spec{Addr: b}}}
	specs, avail := Plan(slots, w.lookup)
	if !avail[0] || !avail[1] || specs[1].InterfaceIndex != 12 || specs[0].InterfaceIndex != 11 {
		t.Fatalf("%+v %v", specs, avail)
	}
	// unpinned slot follows its adapter to a new index
	w.set(b, 20)
	specs, avail = Plan(slots, w.lookup)
	if !avail[1] || specs[1].InterfaceIndex != 20 {
		t.Fatalf("%+v %v", specs, avail)
	}
	// pinned slot becomes unavailable when another adapter owns the address
	w.set(a, 99)
	specs, avail = Plan(slots, w.lookup)
	if avail[0] || specs[0].InterfaceIndex != 11 {
		t.Fatalf("pinned slot moved: %+v %v", specs, avail)
	}
	// adapter gone
	w.set(a, 0)
	w.set(b, 0)
	if _, avail = Plan(slots, w.lookup); avail[0] || avail[1] {
		t.Fatalf("%v", avail)
	}
	// unspecified bind is untracked: stays available and keeps its spec
	un := []Slot{{Spec: uplink.Spec{Addr: netip.IPv4Unspecified(), InterfaceIndex: 7}}}
	specs, avail = Plan(un, w.lookup)
	if !avail[0] || specs[0].InterfaceIndex != 7 {
		t.Fatalf("%+v %v", specs, avail)
	}
}

func TestRunUpdatesOnlyOnChangeAndRetries(t *testing.T) {
	w := &world{m: map[netip.Addr]int{a: 11, b: 12}}
	slots := []Slot{{Spec: uplink.Spec{Addr: a}}, {Spec: uplink.Spec{Addr: b}}}
	var mu sync.Mutex
	var calls [][]bool
	failNext := true
	update := func(_ []uplink.Spec, avail []bool) error {
		mu.Lock()
		defer mu.Unlock()
		if failNext {
			failNext = false
			return errors.New("transient")
		}
		calls = append(calls, append([]bool(nil), avail...))
		return nil
	}
	var errs int
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, 20*time.Millisecond, slots, w.lookup, update, func(error) { mu.Lock(); errs++; mu.Unlock() })
		close(done)
	}()
	time.Sleep(150 * time.Millisecond) // nothing changed: no update
	mu.Lock()
	if len(calls) != 0 || errs != 0 {
		t.Fatalf("update without a change: %v %d", calls, errs)
	}
	mu.Unlock()
	w.set(b, 0) // adapter b disappears; first attempt fails, the retry succeeds
	time.Sleep(200 * time.Millisecond)
	w.set(b, 12)
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if errs != 1 || len(calls) != 2 || calls[0][1] || !calls[1][1] {
		t.Fatalf("errs=%d calls=%v", errs, calls)
	}
}
