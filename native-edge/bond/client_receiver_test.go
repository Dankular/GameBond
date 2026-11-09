package bond

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// clientServerPair wires a client Receiver (two uplinks) to a server Receiver
// through an in-memory network. Each client socket has its own source address,
// as two physical adapters would.
type clientServerPair struct {
	t      *testing.T
	client *Receiver
	server *Receiver
	now    time.Time
	srv    netip.AddrPort
	src    [2]netip.AddrPort
	drop   [2]bool // blackhole uplink i in both directions
}

func newClientServerPair(t *testing.T) *clientServerPair {
	t.Helper()
	key, session := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 16)
	cc, _ := NewCodec(key, session, "client")
	sc, _ := NewCodec(key, session, "server")
	cr, err := NewReceiver(cc, 1400)
	if err != nil {
		t.Fatal(err)
	}
	sr, _ := NewReceiver(sc, 1400)
	cr.probeInterval, sr.probeInterval = 250*time.Millisecond, 250*time.Millisecond
	p := &clientServerPair{t: t, client: cr, server: sr, now: time.Unix(5000, 0),
		srv: netip.MustParseAddrPort("203.0.113.1:4433"),
		src: [2]netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:5000"), netip.MustParseAddrPort("198.51.100.2:5000")}}
	for i := range p.src {
		if err := cr.AddClientPath(i, p.srv, p.now); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// deliver pushes datagrams to the opposite side until the exchange settles.
func (p *clientServerPair) deliver(fromClient bool, out ReceiveResult) {
	type item struct {
		fromClient bool
		d          Datagram
	}
	queue := make([]item, 0, len(out.Send))
	for _, d := range out.Send {
		queue = append(queue, item{fromClient, d})
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		var res ReceiveResult
		var err error
		if it.fromClient {
			if p.drop[it.d.Local] {
				continue
			}
			res, err = p.server.ReceiveOn(0, it.d.Frame, p.src[it.d.Local], p.now)
			for _, r := range res.Send {
				queue = append(queue, item{false, r})
			}
		} else {
			local := -1
			for i, s := range p.src {
				if s == it.d.Endpoint {
					local = i
				}
			}
			if local < 0 || p.drop[local] {
				continue
			}
			res, err = p.client.ReceiveOn(local, it.d.Frame, p.srv, p.now)
			for _, r := range res.Send {
				queue = append(queue, item{true, r})
			}
		}
		if err != nil {
			p.t.Fatal(err)
		}
	}
}

func (p *clientServerPair) step() {
	p.now = p.now.Add(250 * time.Millisecond)
	co, err := p.client.Tick(p.now)
	if err != nil {
		p.t.Fatal(err)
	}
	p.deliver(true, co)
	so, err := p.server.Tick(p.now)
	if err != nil {
		p.t.Fatal(err)
	}
	p.deliver(false, so)
}

func (p *clientServerPair) readyClientPaths() int {
	n := 0
	for _, path := range p.client.paths {
		if path.ready {
			n++
		}
	}
	return n
}

func TestClientReceiverHandshakesEveryUplinkAgainstServer(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 8 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	if p.readyClientPaths() != 2 {
		t.Fatalf("client paths ready = %d, want 2", p.readyClientPaths())
	}
	if !p.client.handshake.hasPeer || p.client.handshake.peer != p.server.codec.Prefix {
		t.Fatal("client did not adopt the server prefix")
	}
	if p.server.ReadyPaths(p.now) != 2 {
		t.Fatalf("server ready paths = %d, want 2 (one per client uplink)", p.server.ReadyPaths(p.now))
	}
	// Probes then flow both ways and produce an RTT sample per uplink.
	for i := 0; i < 6; i++ {
		p.step()
	}
	for key, path := range p.client.paths {
		if !path.hasRTT || path.probeAcked == 0 {
			t.Fatalf("uplink %d has no RTT sample (acked %d)", key.Local, path.probeAcked)
		}
	}
}

func TestClientReceiverRecoversAnUplinkAfterBlackhole(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 8 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	p.drop[1] = true
	for i := 0; i < 20; i++ { // silent for > 3 s: uplink 1 must drop out and re-handshake
		p.step()
	}
	if p.client.paths[PathKey{1, p.srv}].ready {
		t.Fatal("blackholed uplink still ready")
	}
	if !p.client.paths[PathKey{0, p.srv}].ready {
		t.Fatal("healthy uplink lost readiness")
	}
	p.drop[1] = false
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	if p.readyClientPaths() != 2 {
		t.Fatal("uplink did not recover after the blackhole ended")
	}
}

func TestClientReceiverIgnoresUnconfiguredSources(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 8 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	frame, _ := p.server.codec.Encode(Probe, probe(1))
	before := p.client.Stats().Malformed
	out, err := p.client.ReceiveOn(0, frame, netip.MustParseAddrPort("192.0.2.77:4433"), p.now)
	if err != nil || len(out.Send) != 0 || p.client.Stats().Malformed != before+1 {
		t.Fatalf("unconfigured source not dropped: %+v malformed %d err %v", out, p.client.Stats().Malformed, err)
	}
}

func TestServerReceiverStillRejectsAddClientPath(t *testing.T) {
	f := newReceiverFixture(t)
	if err := f.r.AddClientPath(0, f.endpoint, f.now); err == nil {
		t.Fatal("server receiver accepted a client path")
	}
}
