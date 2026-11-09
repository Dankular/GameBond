package bond

import "testing"

// Replicated copies are scored by the receiver and the score is reported back
// to the sender, which feeds it to AdaptiveQoS as the only data-path loss
// evidence (Node._note_copy / COPY_REPORT).
func TestReplicatedCopiesAreScoredAndReported(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	for i := 0; i < 8; i++ {
		p.step()
	}
	send := func(payload string, onPath ...int) {
		frame, err := p.client.codec.Encode(DataCopy, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range onPath {
			res, err := p.server.ReceiveOn(0, frame, p.src[i], p.now)
			if err != nil {
				t.Fatal(err)
			}
			p.deliver(false, res)
		}
	}
	for i := 0; i < 10; i++ {
		send("both", 0, 1)
	}
	for i := 0; i < 6; i++ {
		send("only-path-0", 0) // path 1 never delivers its copy
	}
	for i := 0; i < 8; i++ {
		p.step()
	}
	var seen, missed [2]uint64
	for k, path := range p.server.paths {
		for i := range p.src {
			if k.Remote == p.src[i] {
				seen[i], missed[i] = path.copySeen, path.copyMissed
			}
		}
	}
	if seen[0] != 16 || missed[0] != 0 || seen[1] != 10 || missed[1] != 6 {
		t.Fatalf("server scores seen=%v missed=%v", seen, missed)
	}
	// The client learned its copies' fate through COPY_REPORT.
	var reported [2][3]uint64
	for k, path := range p.client.paths {
		reported[k.Local] = path.peerCopy
	}
	if reported[0] != [3]uint64{16, 0, 0} || reported[1] != [3]uint64{10, 6, 0} {
		t.Fatalf("client reports %v", reported)
	}
}

// A copy that arrives after its path was counted missed is late, not missed.
func TestLateCopyReversesMissedCount(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	for i := 0; i < 8; i++ {
		p.step()
	}
	frame, _ := p.client.codec.Encode(DataCopy, []byte("x"))
	res, _ := p.server.ReceiveOn(0, frame, p.src[0], p.now)
	p.deliver(false, res)
	for i := 0; i < 4; i++ {
		p.step() // resolves: path 1 missed
	}
	res, _ = p.server.ReceiveOn(0, frame, p.src[1], p.now)
	p.deliver(false, res)
	for k, path := range p.server.paths {
		if k.Remote == p.src[1] && (path.copyMissed != 0 || path.copyLate != 1 || !path.hasCopyLag) {
			t.Fatalf("path 1: missed=%d late=%d", path.copyMissed, path.copyLate)
		}
	}
}
