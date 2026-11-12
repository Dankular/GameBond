package client

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"gamebond.local/nativeedge/carrier"
	"gamebond.local/nativeedge/uplink"
)

// gate is a UDP forwarder between the client and the server that can drop
// everything (a UDP-hostile network).
type gate struct {
	conn    *net.UDPConn
	blocked atomic.Bool
}

func newGate(t *testing.T, server netip.AddrPort) *gate {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(server))
	if err != nil {
		t.Fatal(err)
	}
	g := &gate{conn: conn}
	var mu sync.Mutex
	var client *net.UDPAddr
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = from
			mu.Unlock()
			if !g.blocked.Load() {
				up.Write(buf[:n])
			}
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			c := client
			mu.Unlock()
			if c != nil && !g.blocked.Load() {
				conn.WriteToUDP(buf[:n], c)
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); up.Close() })
	return g
}

// With UDP dropped the uplink falls back to the stream carrier and keeps
// delivering; when UDP returns, the recovery HELLO moves it back.
func TestCarrierFallbackAndUDPRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	key, session := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 16)
	var received atomic.Int64
	server := loopbackServer(t, ctx, key, session, func([]byte) { received.Add(1) })
	g := newGate(t, server)
	relay, err := carrier.NewRelay(carrier.RelayConfig{Bind: "127.0.0.1:0", UDPPeer: server.String(), Key: key, Session: session, Mode: "tcp", MaxClients: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	set := carrier.DefaultSettings(carrier.StreamEndpoint{Mode: "tcp", Port: relay.Addr().(*net.TCPAddr).Port})
	set.FallbackAfter, set.RecoveryInterval = .5, .5
	lo := netip.MustParseAddr("127.0.0.1")
	qosSet := bond.DefaultQoSSettings()
	var delivered atomic.Int64
	c, err := New(Config{Key: key, Session: session, Server: g.conn.LocalAddr().(*net.UDPAddr).AddrPort(),
		Uplinks: []uplink.Spec{{Addr: lo}}, Outer: &set, QoS: &qosSet, Deliver: func([]byte) { delivered.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	go c.Run(ctx)
	wait := func(what string, cond func() bool) {
		t.Helper()
		end := time.Now().Add(15 * time.Second)
		for !cond() {
			if time.Now().After(end) {
				t.Fatalf("%s: %+v carrier=%+v", what, c.Snapshot().Receiver, c.Snapshot().Carrier)
			}
			c.Send(make([]byte, 200), "t", 5*time.Second)
			time.Sleep(20 * time.Millisecond)
		}
	}
	mode := func() string {
		if s := c.Snapshot(); len(s.Carrier) > 0 {
			return s.Carrier[0].Mode
		}
		return ""
	}
	wait("ready", func() bool { return c.Snapshot().Ready == 1 && mode() == "udp" })
	base := received.Load()
	wait("udp delivery", func() bool { return received.Load() > base+20 })

	g.blocked.Store(true)
	wait("fallback", func() bool { return mode() == "tcp" && c.Snapshot().Carrier[0].Ready })
	base = received.Load()
	wait("delivery over the stream", func() bool { return received.Load() > base+20 })

	g.blocked.Store(false)
	wait("recovery to udp", func() bool { return mode() == "udp" })
	base = received.Load()
	wait("delivery after recovery", func() bool { return received.Load() > base+20 })
	if q := c.Snapshot().QoS; q == nil || q["enabled"] != true {
		t.Fatalf("qos stats missing: %v", q)
	}
	if n := c.Snapshot().Carrier[0].Counters["udp_recoveries"]; n < 1 {
		t.Fatalf("udp_recoveries=%d", n)
	}
}
