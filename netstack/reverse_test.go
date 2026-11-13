package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// twoStacks joins a "client" stack (10.77.0.2, catch-all on) to an "exit" stack (10.77.0.1).
func twoStacks(t *testing.T, p reversePolicy) (exit *netstack.Net) {
	t.Helper()
	a, na, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	b, nb, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	go pump(a, b)
	go pump(b, a)
	if err := enableReverse(na, p); err != nil {
		t.Fatal(err)
	}
	return nb
}

func TestReverseTCPReachesALocalServiceOnAnyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	exit := twoStacks(t, defaultReversePolicy())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := exit.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.77.0.2:"+strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial through the catch-all: %v", err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("reverse\n"), 4096)
	go func() { c.Write(msg) }()
	got := make([]byte, len(msg))
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %v", err)
	}
}

func TestReverseRefusesPortsNobodyListensOn(t *testing.T) {
	// a port that was just free
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	exit := twoStacks(t, defaultReversePolicy())
	before := reverseStats.TCPRefused.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if c, err := exit.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.77.0.2:"+strconv.Itoa(port))); err == nil {
		c.Close()
		t.Fatal("a closed port must be refused")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("refusal took %v, want an immediate reset", time.Since(start))
	}
	if reverseStats.TCPRefused.Load() == before {
		t.Fatal("refusal not counted")
	}
}

func TestReversePolicyCanDenyAPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			} else {
				return
			}
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	p := defaultReversePolicy()
	p.Allow = func(_ string, q uint16) bool { return q != port }
	exit := twoStacks(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := exit.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.77.0.2:"+strconv.Itoa(int(port)))); err == nil {
		c.Close()
		t.Fatal("denied port was forwarded")
	}
}

func TestReverseUDPRelaysBothWays(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	exit := twoStacks(t, defaultReversePolicy())
	c, err := exit.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.77.0.2:"+strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 5; i++ {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "echo:ping" {
			t.Fatalf("round %d: %q %v", i, buf[:n], err)
		}
	}
}

// Outbound connections from the client stack must keep working with the handlers installed.
func TestReverseDoesNotBreakOutboundDials(t *testing.T) {
	a, na, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	b, nb, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	go pump(a, b)
	go pump(b, a)
	if err := enableReverse(na, defaultReversePolicy()); err != nil {
		t.Fatal(err)
	}
	l, err := nb.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:7000"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, err := na.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.77.0.1:7000"))
	if err != nil {
		t.Fatalf("outbound dial broke: %v", err)
	}
	defer c.Close()
	c.Write([]byte("hi"))
	buf := make([]byte, 2)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("outbound echo: %q %v", buf, err)
	}
}
