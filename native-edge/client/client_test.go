package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/uplink"
)

// loopbackServer is a minimal Go GB03 server: one socket, Receiver ticks.
func loopbackServer(t *testing.T, ctx context.Context, key, session []byte, got func([]byte)) netip.AddrPort {
	t.Helper()
	codec, _ := bond.NewCodec(key, session, "server")
	r, err := bond.NewReceiver(codec, 1400)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	send := func(res bond.ReceiveResult) {
		for _, d := range res.Send {
			conn.WriteToUDPAddrPort(d.Frame, d.Endpoint)
		}
		for _, p := range res.Deliver {
			got(p)
		}
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			mu.Lock()
			res, _ := r.ReceiveOn(0, buf[:n], from, time.Now())
			send(res)
			mu.Unlock()
		}
	}()
	go func() {
		tk := time.NewTicker(5 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				conn.Close()
				return
			case <-tk.C:
				mu.Lock()
				res, _ := r.Tick(time.Now())
				send(res)
				mu.Unlock()
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestClientRunLoopDeliversOverTwoPinnedUplinks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var received atomic.Int64
	seen := sync.Map{}
	server := loopbackServer(t, ctx, key, session, func(p []byte) {
		if _, dup := seen.LoadOrStore(binary.BigEndian.Uint32(p), true); !dup {
			received.Add(1)
		}
	})
	lo := netip.MustParseAddr("127.0.0.1")
	c, err := New(Config{Key: key, Session: session, Server: server, Uplinks: []uplink.Spec{{Addr: lo}, {Addr: lo}},
		Policies: []bond.PathPolicy{{Role: bond.Primary, UploadMbps: 50, DownloadMbps: 50}, {Role: bond.Primary, UploadMbps: 50, DownloadMbps: 50}},
		Discover: true, Failover: true, Deliver: func([]byte) {}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(8 * time.Second)
	for c.Snapshot().Ready < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("uplinks never ready: %+v", c.Snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(600 * time.Millisecond) // RTT samples and policy confirmation
	const total = 2000
	for i := 0; i < total; i++ {
		p := make([]byte, 800)
		binary.BigEndian.PutUint32(p, uint32(i))
		for !c.Send(p, "t", 10*time.Second) {
			time.Sleep(time.Millisecond)
		}
	}
	for received.Load() < total {
		if time.Now().After(deadline.Add(6 * time.Second)) {
			t.Fatalf("delivered %d/%d, snapshot %+v", received.Load(), total, c.Snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
	snap := c.Snapshot()
	used := 0
	for _, p := range snap.Paths {
		if p.WireTX > 200_000 {
			used++
		}
	}
	if used != 2 {
		t.Fatalf("striping used %d uplinks, want 2", used)
	}
	t.Logf("delivered %d, uplinks carrying payload %d, sender %+v", received.Load(), used, snap.Sender)
	cancel()
	<-done
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

// Paced sends used to stall near 60 Mbit/s whatever the policy, because the loop
// slept on a coarse timer between paced releases. With a 100 Mbit/s policy on
// each of two uplinks the client must now move well past that.
func TestPacedThroughputIsNotCappedByTimerGranularity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var received atomic.Int64
	var first, last atomic.Int64
	server := loopbackServer(t, ctx, key, session, func(p []byte) {
		now := time.Now().UnixNano()
		first.CompareAndSwap(0, now)
		last.Store(now)
		received.Add(1)
	})
	lo := netip.MustParseAddr("127.0.0.1")
	pol := bond.PathPolicy{Role: bond.Primary, UploadMbps: 100, DownloadMbps: 100}
	c, err := New(Config{Key: key, Session: session, Server: server, Uplinks: []uplink.Spec{{Addr: lo, Buffer: 4 << 20}, {Addr: lo, Buffer: 4 << 20}},
		Policies: []bond.PathPolicy{pol, pol}, InitialMbps: 1000, MaxMbps: 4000, Deliver: func([]byte) {}})
	if err != nil {
		t.Fatal(err)
	}
	go c.Run(ctx)
	for c.Snapshot().Ready < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(800 * time.Millisecond)
	const total = 20000
	payload := make([]byte, 1000)
	for i := 0; i < total; i++ {
		for !c.Send(payload, "p", 30*time.Second) {
			time.Sleep(time.Millisecond)
		}
	}
	for received.Load() < total {
		if ctx.Err() != nil {
			t.Fatalf("delivered %d/%d", received.Load(), total)
		}
		time.Sleep(20 * time.Millisecond)
	}
	seconds := float64(last.Load()-first.Load()) / 1e9
	mbit := float64(total) * 8000 / seconds / 1e6
	t.Logf("paced 2x100 Mbit/s policy -> %.1f Mbit/s over %.2fs", mbit, seconds)
	if mbit < 120 {
		t.Fatalf("throughput %.1f Mbit/s is at the old ~60 Mbit/s timer-granularity ceiling", mbit)
	}
}

func TestDFEnforcedFollowsPathMTUDiscovery(t *testing.T) {
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	server := netip.MustParseAddrPort("127.0.0.1:9")
	lo := netip.MustParseAddr("127.0.0.1")
	for _, discover := range []bool{false, true} {
		c, err := New(Config{Key: key, Session: session, Server: server, Uplinks: []uplink.Spec{{Addr: lo}},
			Policies: []bond.PathPolicy{{Role: bond.Primary, UploadMbps: 50, DownloadMbps: 50}}, Discover: discover, Deliver: func([]byte) {}})
		if err != nil {
			t.Fatal(err)
		}
		if got := c.DFEnforced(); len(got) != 1 || got[0] != discover {
			t.Errorf("discover=%v: %v", discover, got)
		}
		c.closeConns()
	}
}
