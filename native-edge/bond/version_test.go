package bond

import "testing"

func TestClientAndServerLearnEachOthersBuild(t *testing.T) {
	p := newClientServerPair(t)
	p.client.SetVersion("c11e47aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	p.server.SetVersion("5e47e4bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	for i := 0; i < 12; i++ {
		p.step()
	}
	if l, peer := p.client.Versions(); l != "c11e47aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || peer != "5e47e4bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("client sees local=%q peer=%q", l, peer)
	}
	if _, peer := p.server.Versions(); peer != "c11e47aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("server sees client %q", peer)
	}
}

// A server built before the version frames never answers; the client keeps asking gently and
// everything else keeps working.
func TestVersionFramesAreHarmlessToAnOlderPeer(t *testing.T) {
	p := newClientServerPair(t)
	p.client.SetVersion("abc")
	for i := 0; i < 12; i++ {
		p.step()
	}
	if p.client.stats.Malformed != 0 || p.server.stats.Malformed != 0 {
		t.Fatalf("malformed counters moved: client %d server %d", p.client.stats.Malformed, p.server.stats.Malformed)
	}
	if p.readyClientPaths() != 2 {
		t.Fatal("paths not ready")
	}
}
