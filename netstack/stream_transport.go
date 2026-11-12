package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/stream"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// The bond-aware stream transport: TCP connections to the internet are carried
// as streams to a gateway on the exit server (10.77.0.1:4436), which dials the
// destination. Loss recovery and congestion control then run across both links
// instead of end to end. Any failure falls back to the ordinary netstack dial.
var (
	streamEP       atomic.Pointer[stream.Endpoint]
	streamFailures atomic.Int32
	streamPause    atomic.Int64 // unix nanos until which streams are skipped
)

type remoteConn interface {
	net.Conn
	CloseWrite() error
}

// udpAdapter turns a connected UDP socket into the PacketConn the endpoint wants.
type udpAdapter struct {
	c    net.Conn
	peer net.Addr
}

func (u udpAdapter) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := u.c.Read(p)
	return n, u.peer, err
}
func (u udpAdapter) WriteTo(p []byte, _ net.Addr) (int, error) { return u.c.Write(p) }
func (u udpAdapter) Close() error                              { return u.c.Close() }

func startStreamTransport(stack *netstack.Net) {
	if _, err := os.Stat(`D:\Dev Proj\Speedify\.runtime
o-stream`); err == nil || os.Getenv("GAMEBOND_STREAM") == "0" {
		return
	}
	gw := netip.MustParseAddrPort("10.77.0.1:4436")
	c, err := stack.DialUDPAddrPort(netip.AddrPort{}, gw)
	if err != nil {
		return
	}
	peer := net.UDPAddrFromAddrPort(gw)
	streamEP.Store(stream.NewEndpoint(udpAdapter{c, peer}, peer, stream.Config{ReorderHint: func() time.Duration { return 25 * time.Millisecond }}))
}

func streamTarget(t netip.AddrPort) bool {
	a := t.Addr()
	return !a.IsLoopback() && !a.IsLinkLocalUnicast() && !(a.Is4() && a.As4()[0] == 10 && a.As4()[1] == 77)
}

// dialTCP opens a connection to target through the stream gateway when it is
// healthy, otherwise through the userspace TCP stack.
func dialTCP(ctx context.Context, stack *netstack.Net, target netip.AddrPort) (remoteConn, error) {
	if ep := streamEP.Load(); ep != nil && streamTarget(target) && time.Now().UnixNano() > streamPause.Load() {
		s, err := ep.Dial(target.String(), 2500*time.Millisecond)
		if err == nil {
			streamFailures.Store(0)
			return &loggedStream{s.(*stream.Stream), time.Now()}, nil
		}
		if errors.Is(err, stream.ErrRefused) {
			streamFailures.Store(0)
			return nil, err
		}
		// A refusal means the gateway answered but the destination did not, so
		// only repeated silence should pause the transport.
		if streamFailures.Add(1) >= 3 {
			streamPause.Store(time.Now().Add(30 * time.Second).UnixNano())
			streamFailures.Store(0)
		}
	}
	return stack.DialContextTCPAddrPort(ctx, target)
}

type loggedStream struct {
	*stream.Stream
	start time.Time
}

func (l *loggedStream) Close() error {
	st, cwnd, rtt := l.Stream.Stats()
	if st.BytesAcked+st.BytesDelivered > 1<<20 {
		if f, err := os.OpenFile(`D:\Dev Proj\Speedify\.runtime\stream-stats.log`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(f, "%s dur=%v cwnd=%d srtt=%v %+v\n", time.Now().Format("15:04:05"), time.Since(l.start).Round(time.Millisecond), cwnd, rtt, st)
			f.Close()
		}
	}
	return l.Stream.Close()
}
