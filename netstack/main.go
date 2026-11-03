// A driver-free smoke test of WireGuard's gVisor netstack adapter.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// pump connects only in-memory IP devices. No host socket or route is used.
func pump(src, dst tun.Device) {
	buf := make([]byte, 65535)
	sizes := make([]int, 1)
	for {
		n, err := src.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			return
		}
		if n == 1 {
			if _, err = dst.Write([][]byte{buf[:sizes[0]]}, 0); err != nil {
				return
			}
		}
	}
}

func smoke() error {
	a, na, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	if err != nil {
		return err
	}
	b, nb, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	if err != nil {
		a.Close()
		return err
	}
	// This short-lived harness exits after its result. Keep the pumps alive until
	// process exit rather than closing devices while a peer can still inject.
	if len(os.Args) == 2 && os.Args[1] == "--transport-stdio" {
		bridgeDevices(a, b)
	} else {
		go pump(a, b)
		go pump(b, a)
	}
	deadline := time.Now().Add(8 * time.Second)
	listener, err := nb.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:8080"))
	if err != nil {
		return err
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(deadline)
		_, err = io.Copy(conn, conn)
		serverDone <- err
	}()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	tcp, err := na.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.77.0.1:8080"))
	if err != nil {
		return err
	}
	tcp.SetDeadline(deadline)
	payload := bytes.Repeat([]byte("GameBond-netstack-TCP\n"), 2048)
	written := make(chan error, 1)
	go func() { _, err := io.Copy(tcp, bytes.NewReader(payload)); written <- err }()
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(tcp, reply)
	if err != nil {
		tcp.Close()
		return err
	}
	if err = <-written; err != nil {
		tcp.Close()
		return err
	}
	if !bytes.Equal(payload, reply) {
		tcp.Close()
		return fmt.Errorf("TCP payload mismatch")
	}
	tcp.Close()
	if err = <-serverDone; err != nil {
		return err
	}
	udpServer, err := nb.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:8081"))
	if err != nil {
		return err
	}
	defer udpServer.Close()
	udpClient, err := na.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.77.0.1:8081"))
	if err != nil {
		return err
	}
	defer udpClient.Close()
	udpServer.SetDeadline(deadline)
	udpClient.SetDeadline(deadline)
	udpBytes := 0
	for i := 0; i < 100; i++ {
		if i == 50 && len(os.Args) == 2 && os.Args[1] == "--transport-stdio" {
			// Tell the harness to blackhole one encrypted path mid-stream.
			if err := writeFrame(2, []byte("blackhole-path-0")); err != nil {
				return err
			}
		}
		// Includes a full inner-MTU UDP datagram (20 IP + 8 UDP + 1252).
		packet := bytes.Repeat([]byte{byte(i)}, 1252)
		if _, err = udpClient.Write(packet); err != nil {
			return err
		}
		buf := make([]byte, 2048)
		n, addr, err := udpServer.ReadFrom(buf)
		if err != nil {
			return err
		}
		if _, err = udpServer.WriteTo(buf[:n], addr); err != nil {
			return err
		}
		n, err = udpClient.Read(buf)
		if err != nil {
			return err
		}
		if !bytes.Equal(buf[:n], packet) {
			return fmt.Errorf("UDP payload mismatch at %d", i)
		}
		udpBytes += n
	}
	output := os.Stdout
	scope := "two in-memory stacks; no physical network or GameBond transport"
	if len(os.Args) == 2 && os.Args[1] == "--transport-stdio" {
		output = os.Stderr
		scope = "IP packets exchanged through external GameBond transport harness"
	}
	return json.NewEncoder(output).Encode(map[string]any{
		"passed": true, "backend": "wireguard-go/gvisor-netstack", "mtu": 1280,
		"tcp_echo_bytes": len(payload), "udp_echo_packets": 100, "udp_echo_bytes": udpBytes,
		"host_adapter_created": false, "host_routes_changed": false,
		"scope": scope,
	})
}

func main() {
	// Bound the entire test, including unexpected library blocking.
	if len(os.Args) != 2 || os.Args[1] != "--proxy-stdio" {
		time.AfterFunc(45*time.Second, func() { fmt.Fprintln(os.Stderr, "netstack test timed out"); os.Exit(1) })
	}
	var err error
	if len(os.Args) == 2 && os.Args[1] == "--proxy-stdio" {
		err = proxyStack()
	} else if len(os.Args) == 2 && os.Args[1] == "--internet-probe" {
		err = internetProbe()
	} else if len(os.Args) == 2 && os.Args[1] == "--download-probe" {
		err = downloadProbe()
	} else if len(os.Args) == 2 && os.Args[1] == "--direct-download-stdio" {
		err = directDownload()
	} else if len(os.Args) == 2 && os.Args[1] == "--capture-stdio" {
		err = captureStack()
	} else if len(os.Args) == 2 && os.Args[1] == "--host-probe" {
		err = hostProbe()
	} else {
		err = smoke()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
