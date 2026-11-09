package client

import (
	"bytes"
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"gamebond.local/nativeedge/uplink"
)

func TestSingleLinkVPNBondsWhenOfflineSlotReturns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var received atomic.Int64
	server := loopbackServer(t, ctx, key, session, func([]byte) { received.Add(1) })
	first := uplink.Spec{Addr: netip.MustParseAddr("127.0.0.1")}
	offline := uplink.Spec{Addr: netip.MustParseAddr("203.0.113.9"), InterfaceIndex: 999999}
	c, err := New(Config{Key: key, Session: session, Server: server, Uplinks: []uplink.Spec{first, offline}, Available: []bool{true, false}, Deliver: func([]byte) {}})
	if err != nil {
		t.Fatal("offline slot prevented single-link startup", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitReady(t, c, 1, 5*time.Second)
	send := func(n int) {
		t.Helper()
		want := received.Load() + int64(n)
		for i := 0; i < n; i++ {
			if !c.Send(make([]byte, 500), "single-to-bonded", 5*time.Second) {
				t.Fatal("queue full")
			}
			time.Sleep(time.Millisecond)
		}
		until := time.Now().Add(5 * time.Second)
		for received.Load() != want {
			if time.Now().After(until) {
				t.Fatalf("delivered %d want %d", received.Load(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	send(100)
	second := uplink.Spec{Addr: netip.MustParseAddr("127.0.0.2")}
	if failed, err := c.UpdateUplinks([]uplink.Spec{first, second}, []bool{true, true}); err != nil || len(failed) != 0 {
		t.Fatal(failed, err)
	}
	waitReady(t, c, 2, 5*time.Second)
	time.Sleep(600 * time.Millisecond)
	before := c.Snapshot().Paths
	send(400)
	time.Sleep(150 * time.Millisecond)
	for i, path := range c.Snapshot().Paths {
		if path.WireTX-before[i].WireTX < 10000 {
			t.Fatalf("path %d did not carry bonded payload", i)
		}
	}
	if failed, err := c.UpdateUplinks([]uplink.Spec{first, second}, []bool{true, false}); err != nil || len(failed) != 0 {
		t.Fatal(failed, err)
	}
	waitReady(t, c, 1, 5*time.Second)
	send(100)
}
