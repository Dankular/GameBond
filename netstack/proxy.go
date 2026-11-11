package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func validTarget(target netip.AddrPort) bool {
	return target.IsValid() && target.Port() != 0 && target.Addr().Is4() && !target.Addr().IsUnspecified() && !target.Addr().IsMulticast() && target.Addr() != netip.MustParseAddr("255.255.255.255")
}

func proxyStack() error {
	device, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	if err != nil {
		return err
	}
	bridgeDevices(device)
	startStreamTransport(stack)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	ready, _ := json.Marshal(map[string]any{"socks": listener.Addr().String(), "mode": "proxy"})
	if err = writeFrame(2, ready); err != nil {
		return err
	}
	go publishApplicationMetrics()
	return serveProxyConnections(listener, func(conn net.Conn) { serveSOCKS(conn, stack, false) })
}

// Slots cover the entire connection lifetime, including idle HTTP keep-alives,
// streaming connections and UDP associations. A desktop capture needs room for
// these alongside new website connections; 64 slots caused new sockets to close.
const maxProxyConnections = 1024

func serveProxyConnections(listener net.Listener, handle func(net.Conn)) error {
	semaphore := make(chan struct{}, maxProxyConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case semaphore <- struct{}{}:
			go func() { defer conn.Close(); defer func() { <-semaphore }(); handle(conn) }()
		default:
			conn.Close()
		}
	}
}

func proxyUDP(control net.Conn, stack *netstack.Net, identity ...*appIdentity) error {
	var announced atomic.Bool
	var app *appIdentity
	if len(identity) > 0 {
		app = identity[0]
	}
	var usage *appUsage
	usageInitialized := false
	var release func()
	defer func() {
		if release != nil {
			release()
		}
	}()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer relay.Close()
	port := relay.LocalAddr().(*net.UDPAddr).Port
	if _, err = control.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
		return err
	}
	control.SetDeadline(time.Time{})
	var mutex sync.Mutex
	flows := make(map[netip.AddrPort]net.Conn)
	deniedTargets := make(map[netip.AddrPort]time.Time)
	defer func() {
		mutex.Lock()
		defer mutex.Unlock()
		for _, flow := range flows {
			flow.Close()
		}
	}()
	go func() { io.Copy(io.Discard, control); relay.Close() }()
	buffer := make([]byte, 65535)
	var owner *net.UDPAddr
	for {
		relay.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, source, err := relay.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		if !source.IP.IsLoopback() || n < 10 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 1 {
			continue
		}
		if owner == nil {
			owner = source
		}
		if source.String() != owner.String() {
			continue
		}
		target := netip.AddrPortFrom(netip.AddrFrom4([4]byte{buffer[4], buffer[5], buffer[6], buffer[7]}), binary.BigEndian.Uint16(buffer[8:10]))
		if !validTarget(target) {
			continue
		}
		if !usageInitialized {
			usageInitialized = true
			usage, release = trackAppConnection(app, target.String())
		}
		mutex.Lock()
		flow := flows[target]
		if flow == nil && len(flows) < 128 {
			if until := deniedTargets[target]; time.Now().Before(until) {
				mutex.Unlock()
				continue
			}
			mutex.Unlock()
			decision := authorizeApplication(app, "udp", target.String())
			mutex.Lock()
			if !decision.Allow {
				if len(deniedTargets) >= 128 {
					for key := range deniedTargets {
						delete(deniedTargets, key)
						break
					}
				}
				deniedTargets[target] = time.Now().Add(time.Second)
				mutex.Unlock()
				continue
			}
			rememberAppDestination(usage, target.String())
			flow, err = stack.DialUDPAddrPort(netip.AddrPort{}, target)
			if err != nil {
				flow = nil
			}
			if err == nil {
				emitAppFlow(app, "udp", flow.LocalAddr().String(), target.String(), decision.Profile)
				flows[target] = flow
				go func(flow net.Conn, target netip.AddrPort, owner *net.UDPAddr) {
					defer flow.Close()
					defer func() {
						mutex.Lock()
						if flows[target] == flow {
							delete(flows, target)
						}
						mutex.Unlock()
					}()
					out := make([]byte, 65535)
					out[3] = 1
					ip := target.Addr().As4()
					copy(out[4:8], ip[:])
					binary.BigEndian.PutUint16(out[8:10], target.Port())
					for {
						flow.SetReadDeadline(time.Now().Add(60 * time.Second))
						n, err := flow.Read(out[10:])
						if err != nil {
							return
						}
						if _, err = relay.WriteToUDP(out[:10+n], owner); err != nil {
							return
						}
						if announced.CompareAndSwap(false, true) {
							emitAppActivity(app, "udp", target.String(), "udp_reply")
						}
						appDownload.Add(uint64(n))
						recordAppDatagram(usage, n, false)
					}
				}(flow, target, owner)
			}
		}
		mutex.Unlock()
		if flow != nil {
			written, _ := flow.Write(buffer[10:n])
			appUpload.Add(uint64(written))
			recordAppDatagram(usage, written, true)
		}
	}
}

func internetProbe() error {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	client := http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}}}
	traceURL := os.Getenv("GAMEBOND_PROBE_TRACE_URL")
	if traceURL == "" {
		traceURL = "https://one.one.one.one/cdn-cgi/trace"
	}
	response, err := client.Get(traceURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return err
	}
	egress := ""
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ip=") {
			egress = strings.TrimPrefix(line, "ip=")
		}
	}
	if response.StatusCode != 200 || egress == "" {
		return fmt.Errorf("invalid HTTPS trace response")
	}
	stunAddress := os.Getenv("GAMEBOND_PROBE_STUN_ADDRESS")
	if stunAddress == "" {
		stunAddress = "stun.cloudflare.com:3478"
	}
	udp, err := net.DialTimeout("udp4", stunAddress, 5*time.Second)
	if err != nil {
		return err
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	// STUN verifies the UDP egress address as well as a reply. A DNS response
	// alone cannot establish UDP capture: proxifiers can bypass port 53.
	query := make([]byte, 20)
	query[1] = 1
	binary.BigEndian.PutUint32(query[4:8], 0x2112a442)
	if _, err = rand.Read(query[8:]); err != nil {
		return err
	}
	if _, err = udp.Write(query); err != nil {
		return err
	}
	answer := make([]byte, 2048)
	n, err := udp.Read(answer)
	if err != nil {
		return err
	}
	if n < 20 || binary.BigEndian.Uint16(answer[:2]) != 0x0101 || string(answer[4:20]) != string(query[4:20]) || int(binary.BigEndian.Uint16(answer[2:4]))+20 != n {
		return fmt.Errorf("invalid STUN response")
	}
	udpEgress := ""
	for offset := 20; offset+4 <= n; {
		kind, length := binary.BigEndian.Uint16(answer[offset:offset+2]), int(binary.BigEndian.Uint16(answer[offset+2:offset+4]))
		offset += 4
		if offset+length > n {
			return fmt.Errorf("invalid STUN attribute")
		}
		if kind == 0x0020 && length == 8 && answer[offset+1] == 1 {
			ip := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				ip[i] = answer[offset+4+i] ^ query[4+i]
			}
			udpEgress = ip.String()
		}
		offset += (length + 3) &^ 3
	}
	if udpEgress == "" || udpEgress != egress {
		return fmt.Errorf("UDP egress %q differs from HTTPS egress %q", udpEgress, egress)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "https_status": response.StatusCode, "egress_ipv4": egress, "udp_egress_ipv4": udpEgress, "udp_stun_bytes": n, "proxy_aware": false})
}

func downloadProbe() error {
	conn, err := net.DialTimeout("tcp4", "10.77.0.1:8080", 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return readDownload(conn, os.Stdout)
}

func directDownload() error {
	device, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	if err != nil {
		return err
	}
	defer device.Close()
	bridgeDevices(device)
	conn, err := stack.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("10.77.0.1:8080"))
	if err != nil {
		return err
	}
	defer conn.Close()
	return readDownload(conn, os.Stderr)
}

func readDownload(conn net.Conn, output io.Writer) error {
	conn.SetDeadline(time.Now().Add(25 * time.Second))
	started := time.Now()
	if _, err := conn.Write([]byte("GBDL110")); err != nil {
		return err
	}
	buffer := make([]byte, 65536)
	var received int64
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			for _, b := range buffer[:n] {
				if b != 'Z' {
					return fmt.Errorf("download integrity mismatch")
				}
			}
			received += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	elapsed := time.Since(started).Seconds()
	return json.NewEncoder(output).Encode(map[string]any{"passed": true, "download_bytes": received, "seconds": elapsed, "application_mbps": float64(received) * 8 / elapsed / 1e6})
}
