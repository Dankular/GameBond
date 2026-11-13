package main

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
)

// emuExit is one exit server as the client sees it: a loopback listener that forwards each emulated
// link's traffic to the real server over its own UDP socket (so the server sees one path per link),
// with an impairment stage in each direction.
type emuExit struct {
	listen    *net.UDPConn
	server    *net.UDPAddr
	up        []*net.UDPConn
	clientAt  []atomic.Pointer[net.UDPAddr]
	toServer  []*shaper
	toClient  []*shaper
	blackhole atomic.Bool
}

// emuNet is the whole emulated network: links x exits.
type emuNet struct {
	links int
	exits []*emuExit
}

// linkIP is the loopback address uplink i binds to; the proxy tells links apart by it.
func linkIP(i int) netip.Addr { return netip.AddrFrom4([4]byte{127, 0, 0, byte(i + 1)}) }

func newEmuNet(links int, servers []string, seed int64, done <-chan struct{}) (*emuNet, error) {
	n := &emuNet{links: links}
	for ei, sv := range servers {
		sa, err := net.ResolveUDPAddr("udp4", sv)
		if err != nil {
			return nil, err
		}
		l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		_ = l.SetReadBuffer(4 << 20)
		_ = l.SetWriteBuffer(4 << 20)
		e := &emuExit{listen: l, server: sa, clientAt: make([]atomic.Pointer[net.UDPAddr], links)}
		for i := 0; i < links; i++ {
			i := i
			u, err := net.ListenUDP("udp4", &net.UDPAddr{})
			if err != nil {
				return nil, err
			}
			_ = u.SetReadBuffer(4 << 20)
			e.up = append(e.up, u)
			e.toServer = append(e.toServer, newShaper(seed+int64(ei*100+i*2), func(b []byte) {
				if !e.blackhole.Load() {
					_, _ = u.WriteToUDP(b, e.server)
				}
			}))
			e.toClient = append(e.toClient, newShaper(seed+int64(ei*100+i*2+1), func(b []byte) {
				if ca := e.clientAt[i].Load(); ca != nil && !e.blackhole.Load() {
					_, _ = e.listen.WriteToUDP(b, ca)
				}
			}))
			go e.toServer[i].run(done)
			go e.toClient[i].run(done)
			go func() { // server -> client for link i
				buf := make([]byte, 65535)
				for {
					k, from, err := u.ReadFromUDP(buf)
					if err != nil {
						select {
						case <-done:
							return
						default:
							continue
						}
					}
					if !from.IP.Equal(e.server.IP) || from.Port != e.server.Port || e.blackhole.Load() {
						continue
					}
					e.toClient[i].Push(append([]byte(nil), buf[:k]...))
				}
			}()
		}
		go func() { // client -> server, link chosen by the loopback source address
			buf := make([]byte, 65535)
			for {
				k, from, err := l.ReadFromUDP(buf)
				if err != nil {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				ip := from.IP.To4()
				if ip == nil || ip[0] != 127 || int(ip[3]) < 1 || int(ip[3]) > links {
					continue
				}
				i := int(ip[3]) - 1
				e.clientAt[i].Store(from)
				if e.blackhole.Load() {
					continue
				}
				e.toServer[i].Push(append([]byte(nil), buf[:k]...))
			}
		}()
		n.exits = append(n.exits, e)
	}
	return n, nil
}

func (n *emuNet) addr(exit int) netip.AddrPort {
	return netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", n.exits[exit].listen.LocalAddr().(*net.UDPAddr).Port))
}

// setLink impairs link i in both directions on every exit.
func (n *emuNet) setLink(i int, c Impair) {
	for _, e := range n.exits {
		e.toServer[i].Set(c)
		e.toClient[i].Set(c)
	}
}

// exitIndex finds the exit behind a loopback address, or -1.
func (n *emuNet) exitIndex(a netip.AddrPort) int {
	for i := range n.exits {
		if n.addr(i) == a {
			return i
		}
	}
	return -1
}
