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

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/uplink"
)

func waitReady(t *testing.T, c *Client, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for c.Snapshot().Ready != want {
		if time.Now().After(deadline) {
			t.Fatalf("ready=%d, want %d: %+v", c.Snapshot().Ready, want, c.Snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUpdateUplinksRebindsAndRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var received atomic.Int64
	seen := sync.Map{}
	server := loopbackServer(t, ctx, key, session, func(p []byte) {
		if _, dup := seen.LoadOrStore(binary.BigEndian.Uint32(p), true); !dup {
			received.Add(1)
		}
	})
	a, b, b2 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	c, err := New(Config{Key: key, Session: session, Server: server, Uplinks: []uplink.Spec{{Addr: a}, {Addr: b}},
		Policies: []bond.PathPolicy{{Role: bond.Primary, UploadMbps: 50, DownloadMbps: 50}, {Role: bond.Primary, UploadMbps: 50, DownloadMbps: 50}},
		Discover: true, Failover: true, Deliver: func([]byte) {}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}, {Addr: b}}, nil); err != ErrNotRunning {
		t.Fatalf("before Run: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	waitReady(t, c, 2, 8*time.Second)
	time.Sleep(600 * time.Millisecond)

	next := 0
	send := func(n int) int64 {
		want := received.Load() + int64(n)
		for i := 0; i < n; i++ {
			p := make([]byte, 400)
			binary.BigEndian.PutUint32(p, uint32(next))
			next++
			for !c.Send(p, "t", 10*time.Second) {
				time.Sleep(time.Millisecond)
			}
		}
		deadline := time.Now().Add(10 * time.Second)
		for received.Load() < want {
			if time.Now().After(deadline) {
				t.Fatalf("delivered %d of %d: %+v", received.Load(), want, c.Snapshot())
			}
			time.Sleep(10 * time.Millisecond)
		}
		return want
	}

	// unchanged: no rebind, uplinks stay ready
	if errs, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}, {Addr: b}}, nil); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	if got := c.Snapshot().Rebinds; got != 0 {
		t.Fatalf("unchanged update rebound %d uplinks", got)
	}

	// slot 1 moves to another address: it handshakes again and carries traffic
	if errs, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}, {Addr: b2}}, nil); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	if got := c.Snapshot().Rebinds; got != 1 {
		t.Fatalf("rebinds=%d, want exactly the one changed uplink", got)
	}
	waitReady(t, c, 2, 8*time.Second)
	time.Sleep(600 * time.Millisecond)
	before := c.Snapshot().Paths
	send(300)
	time.Sleep(300 * time.Millisecond) // the snapshot refreshes every 100 ms
	moved := 0
	for i, p := range c.Snapshot().Paths {
		if p.WireTX > before[i].WireTX {
			moved++
		}
	}
	if moved != 2 {
		t.Fatalf("after the rebind %d uplinks carried data, want 2: %+v", moved, c.Snapshot().Paths)
	}

	// the adapter goes away: the slot is parked, traffic continues on slot 0
	if errs, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}, {Addr: b2}}, []bool{true, false}); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	send(200)
	time.Sleep(3500 * time.Millisecond) // the server side path ages out of "ready"
	if got := c.Snapshot().Ready; got != 1 {
		t.Fatalf("ready=%d with one adapter gone, want 1", got)
	}
	send(200)

	// an address that cannot be bound is reported for that slot only
	errs, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}, {Addr: netip.MustParseAddr("203.0.113.9")}}, nil)
	if err != nil || len(errs) != 1 || errs[0].Slot != 1 || errs[0].Error == "" {
		t.Fatalf("bind failure: %v %v", errs, err)
	}
	if _, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}}, nil); err == nil {
		t.Fatal("changing the slot count was accepted")
	}
	// and it comes back
	if errs, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}, {Addr: b}}, nil); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	waitReady(t, c, 2, 8*time.Second)

	cancel()
	<-done
	if _, err := c.UpdateUplinks([]uplink.Spec{{Addr: a}, {Addr: b}}, nil); err != ErrNotRunning {
		t.Fatalf("after Run: %v", err)
	}
}
