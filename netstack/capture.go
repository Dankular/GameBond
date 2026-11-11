package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// A deliberately restricted SOCKS5 ingress for the synthetic probe only.
// It can reach just the two echo ports inside the private in-memory network.
func captureStack() error {
	a, client, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	if err != nil {
		return err
	}
	b, server, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	if err != nil {
		return err
	}
	bridgeDevices(a, b)
	tcp, err := server.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:8080"))
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(10 * time.Second)); io.Copy(c, c) }()
		}
	}()
	udp, err := server.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:8081"))
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err = udp.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	ready, _ := json.Marshal(map[string]any{"socks": listener.Addr().String()})
	if err := writeFrame(2, ready); err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() { defer conn.Close(); serveSOCKS(conn, client) }()
	}
}

func serveSOCKS(conn net.Conn, stack *netstack.Net, restricted ...bool) error {
	testOnly := len(restricted) == 0 || restricted[0]
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] == 0 {
		return fmt.Errorf("invalid SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	identity, err := authenticateCapture(conn, methods, testOnly)
	if err != nil {
		return err
	}
	var request [10]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[2] != 0 || request[3] != 1 {
		return fmt.Errorf("IPv4 SOCKS only")
	}
	if request[1] == 1 {
		if testOnly && (!bytes.Equal(request[4:8], []byte{10, 77, 0, 1}) || binary.BigEndian.Uint16(request[8:]) != 8080) {
			conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			return fmt.Errorf("target denied")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		target := netip.AddrPortFrom(netip.AddrFrom4([4]byte{request[4], request[5], request[6], request[7]}), binary.BigEndian.Uint16(request[8:]))
		if !validTarget(target) {
			return fmt.Errorf("invalid target")
		}
		decision := authorizeApplication(identity, "tcp", target.String())
		if !decision.Allow {
			conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			return fmt.Errorf("application policy denied connection")
		}
		remote, err := dialTCP(ctx, stack, target)
		if err != nil {
			conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return err
		}
		defer remote.Close()
		emitAppFlow(identity, "tcp", remote.LocalAddr().String(), target.String(), decision.Profile)
		remote.SetDeadline(time.Now().Add(10 * time.Second))
		if !testOnly {
			conn.SetDeadline(time.Time{})
			remote.SetDeadline(time.Time{})
		}
		if _, err = conn.Write([]byte{5, 0, 0, 1, 10, 77, 0, 2, 0, 0}); err != nil {
			return err
		}
		emitAppActivity(identity, "tcp", target.String(), "tcp_connect")
		usage, release := trackAppConnection(identity, target.String())
		defer release()
		done := make(chan struct{})
		go func() {
			io.Copy(countAppWriter(remote, &appUpload, usage, true), conn)
			remote.CloseWrite()
			close(done)
		}()
		_, err = io.Copy(countAppWriter(conn, &appDownload, usage, false), remote)
		conn.Close()
		<-done
		return err
	}
	if request[1] != 3 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("unsupported command")
	}
	if !testOnly {
		return proxyUDP(conn, stack, identity)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer relay.Close()
	remote, err := stack.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.77.0.1:8081"))
	if err != nil {
		return err
	}
	defer remote.Close()
	port := relay.LocalAddr().(*net.UDPAddr).Port
	if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
		return err
	}
	go func() { io.Copy(io.Discard, conn); relay.Close(); remote.Close() }()
	buf := make([]byte, 2048)
	for {
		relay.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := relay.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if !addr.IP.IsLoopback() || n < 10 || !bytes.Equal(buf[:8], []byte{0, 0, 0, 1, 10, 77, 0, 1}) || binary.BigEndian.Uint16(buf[8:10]) != 8081 {
			continue
		}
		if _, err = remote.Write(buf[10:n]); err != nil {
			return err
		}
		remote.SetReadDeadline(time.Now().Add(3 * time.Second))
		count, err := remote.Read(buf[10:])
		if err != nil {
			return err
		}
		if _, err = relay.WriteToUDP(buf[:10+count], addr); err != nil {
			return err
		}
	}
}

// Uses ordinary Windows sockets, with no proxy awareness. Only this executable
// name is selected by the temporary ProxiFyre configuration.
func hostProbe() error {
	tcp, err := net.DialTimeout("tcp4", "10.77.0.1:8080", 4*time.Second)
	if err != nil {
		return err
	}
	tcp.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("GameBond-captured-TCP\n"), 2048)
	done := make(chan error, 1)
	go func() { _, err := io.Copy(tcp, bytes.NewReader(payload)); done <- err }()
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(tcp, reply); err != nil {
		tcp.Close()
		return err
	}
	if err = <-done; err != nil {
		tcp.Close()
		return err
	}
	tcp.Close()
	if !bytes.Equal(payload, reply) {
		return fmt.Errorf("captured TCP mismatch")
	}
	udp, err := net.DialTimeout("udp4", "10.77.0.1:8081", time.Second)
	if err != nil {
		return err
	}
	defer udp.Close()
	rtts := make([]float64, 0, 100)
	for i := 0; i < 100; i++ {
		packet := bytes.Repeat([]byte{byte(i)}, 1252)
		started := time.Now()
		udp.SetDeadline(time.Now().Add(time.Second))
		if _, err = udp.Write(packet); err != nil {
			return err
		}
		buf := make([]byte, 2048)
		n, err := udp.Read(buf)
		if err != nil {
			return err
		}
		if !bytes.Equal(buf[:n], packet) {
			return fmt.Errorf("captured UDP mismatch")
		}
		rtts = append(rtts, float64(time.Since(started))/float64(time.Millisecond))
	}
	sort.Float64s(rtts)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "tcp_echo_bytes": len(payload), "udp_echo_packets": 100, "udp_echo_bytes": 125200, "proxy_aware": false,
		"udp_rtt_ms": map[string]float64{"p50": rtts[49], "p95": rtts[94], "max": rtts[99]}})
}
