package main

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestSOCKSApplicationCountersExcludeHandshakeAndIPHeaders(t *testing.T) {
	appUpload.Store(0)
	appDownload.Store(0)
	a, client, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, server, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pump := func(from, to tun.Device) {
		buffer := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			n, err := from.Read([][]byte{buffer}, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				if _, err = to.Write([][]byte{buffer[:sizes[0]]}, 0); err != nil {
					return
				}
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	listener, err := server.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	host, proxy := net.Pipe()
	defer host.Close()
	host.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { defer proxy.Close(); serveSOCKS(proxy, client, false) }()
	if _, err = host.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(host, greeting); err != nil {
		t.Fatal(err)
	}
	if _, err = host.Write([]byte{5, 1, 0, 1, 10, 77, 0, 1, 0x1f, 0x90}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err = io.ReadFull(host, reply); err != nil || reply[1] != 0 {
		t.Fatalf("reply=%v err=%v", reply, err)
	}
	payload := []byte("payload-without-protocol-headers")
	if _, err = host.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err = io.ReadFull(host, echo); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for (appUpload.Load() != uint64(len(payload)) || appDownload.Load() != uint64(len(payload))) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if appUpload.Load() != uint64(len(payload)) || appDownload.Load() != uint64(len(payload)) {
		t.Fatalf("upload=%d download=%d", appUpload.Load(), appDownload.Load())
	}
}
