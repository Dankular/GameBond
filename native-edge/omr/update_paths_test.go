package omr

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"gamebond.local/nativeedge/uplink"
)

func errTotal(c *Client) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.errors["decrypt"] + c.errors["malformed"] + c.errors["clocksync"]
}

func TestUpdatePathsRebindsOnlyChangedSlots(t *testing.T) {
	key := make([]byte, 32)
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, err := NewClient(Config{Key: key, Server: srv.LocalAddr().(*net.UDPAddr).AddrPort(),
		LocalIPs: []string{"127.0.0.1", "127.0.0.2"}, Prefs: []int{1, 7},
		Open: func(ip string, idx int) (*net.UDPConn, error) {
			return uplink.Open(uplink.Spec{Addr: netip.MustParseAddr(ip)})
		}})
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	defer c.Close()

	c.mu.Lock()
	keep, old := c.paths[0], c.paths[1]
	old.tx.total, old.tx.bytes, old.rx.total, old.rx.bytes = 5, 500, 6, 600
	oldConn := old.conn
	c.mu.Unlock()

	// nothing changed: nothing rebound, but the rebind counter still ticks
	if errs, err := c.UpdatePaths([]string{"127.0.0.1", "127.0.0.2"}, nil, nil); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	c.mu.Lock()
	same := c.paths[0] == keep && c.paths[1] == old && c.errors["rebinds"] == 1
	c.mu.Unlock()
	if !same {
		t.Fatal("unchanged slots were rebound")
	}

	// slot 1 moves to a new address
	if errs, err := c.UpdatePaths([]string{"127.0.0.1", "127.0.0.3"}, nil, nil); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	c.mu.Lock()
	fresh := c.paths[1]
	c.mu.Unlock()
	if c.paths[0] != keep || fresh == old || fresh.conn == nil || fresh.localIP != "127.0.0.3" ||
		fresh.conn.LocalAddr().(*net.UDPAddr).IP.String() != "127.0.0.3" {
		t.Fatalf("slot 1 not rebound: %+v", fresh)
	}
	if fresh.tx.total != 5 || fresh.tx.bytes != 500 || fresh.rx.total != 6 || fresh.rx.bytes != 600 {
		t.Fatalf("usage counters lost: %+v %+v", fresh.tx, fresh.rx)
	}
	if fresh.basePref != 7 || fresh.pref != 7 {
		t.Fatalf("custom preference lost: %d/%d", fresh.basePref, fresh.pref)
	}
	if _, err := oldConn.WriteToUDPAddrPort([]byte{1}, srv.LocalAddr().(*net.UDPAddr).AddrPort()); err == nil {
		t.Fatal("old socket still open")
	}

	// the new socket is read: garbage must be counted by the reader goroutine
	before := errTotal(c)
	junk := append(store(time.Now().UnixMicro()&^1, 6), make([]byte, 40)...)
	srv.WriteToUDPAddrPort(junk, fresh.conn.LocalAddr().(*net.UDPAddr).AddrPort())
	deadline := time.Now().Add(3 * time.Second)
	for errTotal(c) == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if errTotal(c) == before {
		t.Fatal("no reader on the rebound socket")
	}

	// adapter goes away, then comes back
	if errs, err := c.UpdatePaths([]string{"127.0.0.1", "127.0.0.3"}, nil, []bool{true, false}); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	c.mu.Lock()
	down := c.paths[1]
	c.mu.Unlock()
	if down.enabled || down.conn != nil || down.reason != "adapter unavailable" {
		t.Fatalf("unavailable slot still enabled: %+v", down)
	}
	if errs, err := c.UpdatePaths([]string{"127.0.0.1", "127.0.0.3"}, nil, []bool{true, true}); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	c.mu.Lock()
	up := c.paths[1]
	c.mu.Unlock()
	if !up.enabled || up.conn == nil {
		t.Fatalf("slot did not come back: %+v", up)
	}

	// a bind failure is reported per slot and leaves the slot disabled
	errs, err := c.UpdatePaths([]string{"127.0.0.1", "203.0.113.9"}, nil, nil)
	if err != nil || len(errs) != 1 || errs[0].Slot != 1 || errs[0].Error == "" {
		t.Fatalf("bind failure not reported: %v %v", errs, err)
	}

	if _, err := c.UpdatePaths([]string{"127.0.0.1"}, nil, nil); err == nil {
		t.Fatal("changing the slot count was accepted")
	}
	if _, err := c.UpdatePaths([]string{"127.0.0.1", "127.0.0.2"}, []int{1}, nil); err == nil {
		t.Fatal("short interface index list accepted")
	}
}

func TestUpdatePathsRoleNeverStaysOff(t *testing.T) {
	key := make([]byte, 32)
	c, err := NewClient(Config{Key: key, Server: netip.MustParseAddrPort("127.0.0.1:9"), LocalIPs: []string{"127.0.0.1"}, Roles: []string{"never"},
		Open: func(ip string, idx int) (*net.UDPConn, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if errs, err := c.UpdatePaths([]string{"127.0.0.1"}, nil, []bool{true}); err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	if p := c.paths[0]; p.enabled || p.reason != "role never" {
		t.Fatalf("%+v", p)
	}
}
