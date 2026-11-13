package main

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Reverse proxy catch-all.
//
// The exit node forwards a public port to this PC's tunnel address (10.77.0.2). The stack here has no
// listener for most ports, so a gVisor transport-protocol handler takes every TCP connection and UDP
// flow that matches no endpoint and relays it to the same port on this PC's loopback. A TCP port with
// nothing listening locally is refused at once (the connection is reset), so only services that are
// actually running are reachable: ports are open everywhere, used only where a program listens.
//
// Outbound traffic is unaffected: the handler runs only for packets that find no endpoint, and the
// connections this stack dials have one.

const (
	reverseMaxTCP   = 1024             // concurrent forwarded TCP connections
	reverseUDPIdle  = 60 * time.Second // an idle UDP flow is closed after this
	reverseDialWait = 2 * time.Second
	reverseMaxUDP   = 512
)

// reverseCounters are readable by tests and the status feed.
type reverseCounters struct {
	TCPAccepted, TCPRefused, UDPFlows, Denied atomic.Uint64
}

var reverseStats reverseCounters

// reversePolicy decides which ports may be forwarded. The default allows everything; the GUI control
// plane will replace Allow later.
type reversePolicy struct {
	Allow func(proto string, port uint16) bool
	// Target maps a public port to the local address the service listens on.
	Target func(proto string, port uint16) string
}

func defaultReversePolicy() reversePolicy {
	return reversePolicy{
		Allow:  func(string, uint16) bool { return true },
		Target: func(_ string, port uint16) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))) },
	}
}

// stackOf reaches the gVisor stack inside a wireguard netstack Net. The type keeps it private, and the
// catch-all needs the transport handler hooks, so the field is read by name; the test pins this to
// the vendored version.
func stackOf(n *netstack.Net) (*stack.Stack, error) {
	f := reflect.ValueOf(n).Elem().FieldByName("stack")
	if !f.IsValid() || f.Type() != reflect.TypeOf((*stack.Stack)(nil)) {
		return nil, fmt.Errorf("netstack layout changed: no stack field")
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(*stack.Stack), nil
}

// enableReverse installs the TCP and UDP catch-all handlers.
func enableReverse(n *netstack.Net, p reversePolicy) error {
	s, err := stackOf(n)
	if err != nil {
		return err
	}
	if p.Allow == nil || p.Target == nil {
		d := defaultReversePolicy()
		if p.Allow == nil {
			p.Allow = d.Allow
		}
		if p.Target == nil {
			p.Target = d.Target
		}
	}
	tcpFwd := tcp.NewForwarder(s, 0, reverseMaxTCP, func(r *tcp.ForwarderRequest) { serveReverseTCP(r, p) })
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) { serveReverseUDP(r, p) })
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return nil
}

func serveReverseTCP(r *tcp.ForwarderRequest, p reversePolicy) {
	port := r.ID().LocalPort
	if !p.Allow("tcp", port) {
		reverseStats.Denied.Add(1)
		r.Complete(true)
		return
	}
	// Dial the local service before accepting, so a closed port is reset instead of left half open.
	local, err := net.DialTimeout("tcp", p.Target("tcp", port), reverseDialWait)
	if err != nil {
		reverseStats.TCPRefused.Add(1)
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		local.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	reverseStats.TCPAccepted.Add(1)
	remote := gonet.NewTCPConn(&wq, ep)
	go relay(remote, local)
}

// relay copies both ways and closes each side's write half when its source ends.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

var udpFlows atomic.Int64

func serveReverseUDP(r *udp.ForwarderRequest, p reversePolicy) {
	port := r.ID().LocalPort
	if !p.Allow("udp", port) {
		reverseStats.Denied.Add(1)
		return
	}
	if udpFlows.Load() >= reverseMaxUDP {
		return
	}
	local, err := net.Dial("udp", p.Target("udp", port))
	if err != nil {
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		local.Close()
		return
	}
	reverseStats.UDPFlows.Add(1)
	udpFlows.Add(1)
	remote := gonet.NewUDPConn(&wq, ep)
	go relayUDP(remote, local)
}

// relayUDP shuttles datagrams until the flow has been idle for reverseUDPIdle.
func relayUDP(remote, local net.Conn) {
	defer udpFlows.Add(-1)
	defer remote.Close()
	defer local.Close()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{}, 2)
	pump := func(dst, src net.Conn) {
		buf := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(reverseUDPIdle))
			n, err := src.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Since(time.Unix(0, last.Load())) < reverseUDPIdle {
					continue // the other direction is still active
				}
				done <- struct{}{}
				return
			}
			last.Store(time.Now().UnixNano())
			if _, err := dst.Write(buf[:n]); err != nil {
				done <- struct{}{}
				return
			}
		}
	}
	go pump(local, remote)
	go pump(remote, local)
	<-done
}

var _ = tcpip.Address{}
