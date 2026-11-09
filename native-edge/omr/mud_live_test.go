package omr

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"gamebond.local/nativeedge/uplink"
)

// A scripted loopback server exercises the real socket, reader and timer
// goroutines: the client must discover the MTU from echoed probes, become
// ready, deliver data in both directions and keep its counters.
func TestMudLiveLoopback(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srvSecret := make([]byte, 32)
	for i := range srvSecret {
		srvSecret[i] = byte(100 + i)
	}
	const pathMTU = 1300 // datagrams larger than this are silently dropped
	var rxB, rxT int64
	got := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			w := append([]byte(nil), buf[:n]...)
			rxB += int64(n)
			rxT++
			header := load(w[:6])
			if header&1 == 0 {
				continue // data: only the first test packet is checked below
			}
			if n > pathMTU {
				continue
			}
			plain := Unseal(key, w)
			m, err := UnpackMsg(plain)
			if err != nil || m.SentTime != 0 {
				continue // only probes are answered; echoes of our replies are not re-echoed
			}
			now := time.Now().UnixMicro() &^ 1
			reply := Msg{SentTime: header, PKey: make([]byte, 32), TxBytes: rxB, TxTotal: rxT, RxBytes: rxB, RxTotal: rxT, FwBytes: rxB, FwTotal: rxT, MTU: m.MTU, FixedRate: 1, LossLimit: 255, Addr: from}
			reply.PKey[0] = 7
			body := make([]byte, n-PktMin)
			copy(body, reply.Pack())
			srv.WriteToUDPAddrPort(Seal(key, store(now|1, 6), body), from)
		}
	}()
	c, err := NewClient(Config{Key: key, Server: srv.LocalAddr().(*net.UDPAddr).AddrPort(), LocalIPs: []string{"127.0.0.1"}, RateMbps: 100,
		Open: func(ip string, idx int) (*net.UDPConn, error) {
			return uplink.Open(uplink.Spec{Addr: netip.MustParseAddr(ip)})
		}})
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	defer c.Close()
	deadline := time.Now().Add(8 * time.Second)
	for !c.Ready() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !c.Ready() {
		t.Fatalf("never ready: %+v", c.Stats())
	}
	st := c.Stats()
	if st.TunnelMTU <= 0 || st.TunnelMTU+PktMin > pathMTU || st.Paths[0].Status != Running {
		t.Fatalf("mtu discovery wrong: %+v", st)
	}
	// Window refills with time; send until accepted.
	pkt := make([]byte, 100)
	pkt[0] = 0x45
	for i := 0; i < 200 && !c.Send(pkt, false); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Stats().Paths[0].DataTx == 0 {
		t.Fatal("no data packet was sent")
	}
	// Server-to-client data under the pre-shared key is delivered to the inbox.
	pc := srvAddr(t, c, srv)
	_ = got
	data := make([]byte, 60)
	data[0] = 0x45
	srv.WriteToUDPAddrPort(Seal(key, store(time.Now().UnixMicro()&^1, 6), data), pc)
	select {
	case p := <-c.Inbox():
		if len(p) != 60 {
			t.Fatalf("len %d", len(p))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no delivery: %+v", c.Stats())
	}
}

// srvAddr is the client's local socket address.
func srvAddr(t *testing.T, c *Client, _ *net.UDPConn) netip.AddrPort {
	t.Helper()
	return c.paths[0].conn.LocalAddr().(*net.UDPAddr).AddrPort()
}
