package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"gamebond.local/nativeedge/uplink"
)

type counted struct {
	n    atomic.Int64
	seen sync.Map
}

func (c *counted) add(p []byte) {
	if _, dup := c.seen.LoadOrStore(binary.BigEndian.Uint32(p), true); !dup {
		c.n.Add(1)
	}
}

func sendN(t *testing.T, c *Client, start, n int, into *counted, within time.Duration) {
	t.Helper()
	want := into.n.Load() + int64(n)
	for i := 0; i < n; i++ {
		p := make([]byte, 400)
		binary.BigEndian.PutUint32(p, uint32(start+i))
		for !c.Send(p, "t", 10*time.Second) {
			time.Sleep(time.Millisecond)
		}
	}
	deadline := time.Now().Add(within)
	for into.n.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d of %d: exit=%+v", into.n.Load(), want, c.Snapshot().Exit)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func failoverClient(t *testing.T, ctx context.Context, key, session []byte, primary, backup netip.AddrPort, switched chan<- string) *Client {
	return failoverClientAfter(t, ctx, key, session, primary, backup, switched, 700*time.Millisecond)
}

func failoverClientAfter(t *testing.T, ctx context.Context, key, session []byte, primary, backup netip.AddrPort, switched chan<- string, after time.Duration) *Client {
	t.Helper()
	c, err := New(Config{Key: key, Session: session, Server: primary, Backups: []netip.AddrPort{backup}, FailoverAfter: after,
		Uplinks:  []uplink.Spec{{Addr: netip.MustParseAddr("127.0.0.1")}, {Addr: netip.MustParseAddr("127.0.0.2")}},
		Policies: []bond.PathPolicy{{Role: bond.Primary, UploadMbps: 50, DownloadMbps: 50}, {Role: bond.Primary, UploadMbps: 50, DownloadMbps: 50}},
		Discover: true, Failover: true, Deliver: func([]byte) {},
		OnSwitch: func(from, to netip.AddrPort, reason string) {
			if switched != nil {
				switched <- to.String()
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	go c.Run(ctx)
	return c
}

func TestFailoverMovesToStandbyWhenActiveServerDies(t *testing.T) {
	probeFirst, probeEvery, probeTimeout = 300*time.Millisecond, time.Hour, 2*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var gotA, gotB counted
	ctxA, killA := context.WithCancel(ctx)
	a := loopbackServer(t, ctxA, key, session, gotA.add)
	b := loopbackServer(t, ctx, key, session, gotB.add)
	switched := make(chan string, 4)
	c := failoverClient(t, ctx, key, session, a, b, switched)
	waitReady(t, c, 2, 8*time.Second)
	sendN(t, c, 0, 200, &gotA, 10*time.Second)

	// the idle probe finds the standby healthy and does not move the session
	deadline := time.Now().Add(6 * time.Second)
	for {
		ex := c.Snapshot().Exit
		if len(ex.Servers) == 2 && ex.Servers[1].State == "reachable" {
			if ex.Active != a || ex.Switches != 0 {
				t.Fatalf("a probe moved the session: %+v", ex)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("standby never reported reachable: %+v", ex)
		}
		time.Sleep(20 * time.Millisecond)
	}

	killA()
	select {
	case to := <-switched:
		if to != b.String() {
			t.Fatalf("switched to %s, want %s", to, b)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("no failover: %+v", c.Snapshot().Exit)
	}
	waitReady(t, c, 2, 8*time.Second)
	sendN(t, c, 1000, 300, &gotB, 10*time.Second)
	ex := c.Snapshot().Exit
	if ex.Active != b || ex.Switches != 1 || ex.Servers[0].Failures != 1 || ex.Servers[0].State != "unreachable" {
		t.Fatalf("exit status after failover: %+v", ex)
	}
	if ex.Servers[0].WireTX == 0 || ex.Servers[1].WireTX == 0 || ex.Servers[1].WireRX == 0 {
		t.Fatalf("each exit should keep the traffic it carried: %+v", ex.Servers)
	}
}

func TestSilenceWithNoReachableStandbyDoesNotSwitch(t *testing.T) {
	probeFirst, probeEvery, probeTimeout = time.Hour, time.Hour, time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var gotA, gotB counted
	ctxA, killA := context.WithCancel(ctx)
	ctxB, killB := context.WithCancel(ctx)
	a := loopbackServer(t, ctxA, key, session, gotA.add)
	b := loopbackServer(t, ctxB, key, session, gotB.add)
	c := failoverClient(t, ctx, key, session, a, b, nil)
	waitReady(t, c, 2, 8*time.Second)
	// the local network is gone: neither server answers
	killA()
	killB()
	time.Sleep(5 * time.Second)
	ex := c.Snapshot().Exit
	if ex.Switches != 0 || ex.Active != a {
		t.Fatalf("switched without any reachable standby: %+v", ex)
	}
	if !ex.Probing {
		t.Fatalf("not looking for a standby while the active server is silent: %+v", ex)
	}
}

func TestBackupsAreRejectedWithCarrierAndDuplicates(t *testing.T) {
	a, b := netip.MustParseAddrPort("203.0.113.1:4433"), netip.MustParseAddrPort("203.0.113.2:4433")
	base := Config{Key: bytes.Repeat([]byte{9}, 32), Session: bytes.Repeat([]byte{8}, 16), Server: a,
		Uplinks: []uplink.Spec{{Addr: netip.MustParseAddr("127.0.0.1")}}, Deliver: func([]byte) {}}
	dup := base
	dup.Backups = []netip.AddrPort{a}
	if _, err := New(dup); err == nil {
		t.Fatal("a backup equal to the primary was accepted")
	}
	ok := base
	ok.Backups = []netip.AddrPort{b}
	c, err := New(ok)
	if err != nil {
		t.Fatal(err)
	}
	c.closeConns()
}

// With a warm standby that is audible, the client does not wait out the conservative FailoverAfter:
// it moves after a few multiples of the active server's own frame gap.
func TestFastFailoverBeatsTheConfiguredSilence(t *testing.T) {
	probeFirst, probeEvery, probeTimeout = 100*time.Millisecond, time.Hour, 2*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var gotA, gotB counted
	ctxA, killA := context.WithCancel(ctx)
	a := loopbackServer(t, ctxA, key, session, gotA.add)
	b := loopbackServer(t, ctx, key, session, gotB.add)
	switched := make(chan string, 4)
	const after = 3 * time.Second
	c := failoverClientAfter(t, ctx, key, session, a, b, switched, after)
	waitReady(t, c, 2, 8*time.Second)
	sendN(t, c, 0, 100, &gotA, 10*time.Second)
	// let the client learn the line's rhythm (fastSamples seconds of frames)
	time.Sleep((fastSamples + 2) * time.Second)
	if ex := c.Snapshot().Exit; len(ex.Servers) != 2 || ex.Servers[1].State != "reachable" || ex.Switches != 0 {
		t.Fatalf("standby should be warm and nothing switched yet: %+v", ex)
	}
	t0 := time.Now()
	killA()
	select {
	case to := <-switched:
		took := time.Since(t0)
		if to != b.String() {
			t.Fatalf("switched to %s, want %s", to, b)
		}
		if took > after*2/3 {
			t.Fatalf("fast path took %v with FailoverAfter=%v", took, after)
		}
		t.Logf("failover after %v (limit %v)", took, after)
	case <-time.After(10 * time.Second):
		t.Fatalf("no failover: %+v", c.Snapshot().Exit)
	}
	waitReady(t, c, 2, 8*time.Second)
	sendN(t, c, 1000, 100, &gotB, 10*time.Second)
	// the old exit is back in the warm set, reported unreachable while it is down (the status
	// snapshot refreshes every 100 ms)
	var ex ExitStatus
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ex = c.Snapshot().Exit; ex.Switches == 1 {
			break
		}
	}
	if len(ex.Servers) != 2 || ex.Servers[0].Active || ex.Servers[0].Failures != 1 {
		t.Fatalf("after failover: %+v", ex)
	}
}

func TestAdaptiveThresholdFollowsTheLongestRecentGap(t *testing.T) {
	f := &failoverState{after: time.Second}
	if got := f.adaptive(); got != time.Second {
		t.Fatalf("with no samples want the configured silence, got %v", got)
	}
	f.gaps = [gapSeconds]time.Duration{60 * time.Millisecond, 70 * time.Millisecond, 80 * time.Millisecond, 900 * time.Millisecond}
	f.gapCount = 4
	// the single 900 ms stall is ignored (second largest is 80 ms): 4 x 80 = 320 ms
	if got := f.adaptive(); got != 320*time.Millisecond {
		t.Fatalf("got %v want 320ms", got)
	}
	f.gaps = [gapSeconds]time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	f.gapCount = 3
	if got := f.adaptive(); got != minFastAfter {
		t.Fatalf("floor: got %v want %v", got, minFastAfter)
	}
	f.gaps = [gapSeconds]time.Duration{400 * time.Millisecond, 500 * time.Millisecond, 600 * time.Millisecond}
	if got := f.adaptive(); got != time.Second {
		t.Fatalf("cap: got %v want 1s", got)
	}
}
