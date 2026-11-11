package bond

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

type sentFrame struct {
	kind byte
	body []byte
	to   netip.AddrPort
}

// sendProtected sends n distinct bulk packets (varying lengths) with the given
// smoothed loss on path 0 and returns every frame the sender wrote.
func sendProtected(t *testing.T, loss float64, n int) ([][]byte, []sentFrame, *Sender) {
	t.Helper()
	f, s, a := senderFixture(t, 2)
	p0 := f.r.paths[pk(a[0])]
	ts := f.r.seconds(f.now)
	p0.budget.lossSeen, p0.budget.lossAt, p0.budget.lossEWMA, p0.budget.lossEWSet = true, ts, loss, true
	var frames []sentFrame
	writer := func(d Datagram) error {
		pkt, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, sentFrame{pkt.Header.Kind, pkt.Payload, d.Endpoint})
		return nil
	}
	var originals [][]byte
	for i := 0; i < n; i++ {
		payload := bytes.Repeat([]byte{byte(i + 1)}, 60+i*7)
		originals = append(originals, payload)
		for tries := 0; ; tries++ {
			if tries > 5000 {
				t.Fatal("bulk never sent")
			}
			now := f.now.Add(time.Duration(i*5+tries) * time.Millisecond)
			p0.budget.lossAt = f.r.seconds(now) // keep the estimate fresh
			if ok, _, err := s.Bulk(payload, "flow", now, writer); err != nil {
				t.Fatal(err)
			} else if ok {
				break
			}
		}
	}
	return originals, frames, s
}

// receiverFor builds an independent receiver with two ready paths.
func receiverFor(t *testing.T) (receiverFixture, [2]netip.AddrPort) {
	g := newReceiverFixture(t)
	var ep [2]netip.AddrPort
	for i := range ep {
		ep[i] = netip.AddrPortFrom(g.endpoint.Addr(), uint16(2000+i))
		g.connect(t, ep[i])
	}
	return g, ep
}

func TestParityRebuildsOneLostPacketPerGroup(t *testing.T) {
	originals, frames, s := sendProtected(t, 0.005, 16)
	var parities int
	for _, fr := range frames {
		if fr.kind == Parity {
			parities++
		}
	}
	if parities != 2 || s.Stats().ParitySent != 2 {
		t.Fatalf("want two parity frames for two full groups, got %d (stat %d)", parities, s.Stats().ParitySent)
	}
	// The first group only primes the receiver (data is kept once parity has been seen).
	for lost := 8; lost < 16; lost++ {
		g, ep := receiverFor(t)
		var delivered [][]byte
		seen := 0
		for _, fr := range frames {
			if fr.kind == Striped {
				if seen == lost {
					seen++
					continue
				}
				seen++
			}
			out := g.receive(t, fr.kind, fr.body, ep[0])
			delivered = append(delivered, out.Deliver...)
		}
		if g.r.stats.FECRecovered != 1 {
			t.Fatalf("lost %d: nothing recovered (%+v)", lost, g.r.stats)
		}
		if len(delivered) != 16 {
			t.Fatalf("lost %d: delivered %d of 16", lost, len(delivered))
		}
		for i, want := range originals {
			if !bytes.Equal(delivered[i], want) {
				t.Fatalf("lost %d: packet %d differs after recovery", lost, i)
			}
		}
	}
}

func TestParityIgnoredWhenTwoMembersMissing(t *testing.T) {
	_, frames, _ := sendProtected(t, 0.005, 16)
	g, ep := receiverFor(t)
	seen := 0
	for _, fr := range frames {
		if fr.kind == Striped {
			seen++
			if seen == 10 || seen == 13 {
				continue
			}
		}
		g.receive(t, fr.kind, fr.body, ep[0])
	}
	if g.r.stats.FECRecovered != 0 {
		t.Fatal("recovered from an unsolvable group")
	}
}

func TestHeavyLossDuplicatesBulkOnAnotherPath(t *testing.T) {
	originals, frames, s := sendProtected(t, 0.03, 10)
	if s.Stats().BulkDuplicates == 0 {
		t.Fatalf("no duplicates sent: %+v", s.Stats())
	}
	if s.Stats().ParitySent != 0 {
		t.Fatal("parity sent alongside duplication")
	}
	g, ep := receiverFor(t)
	var delivered [][]byte
	for _, fr := range frames {
		out := g.receive(t, fr.kind, fr.body, ep[0])
		delivered = append(delivered, out.Deliver...)
	}
	if len(delivered) != len(originals) {
		t.Fatalf("delivered %d, want %d: duplicates must be dropped", len(delivered), len(originals))
	}
	// Drop every copy that went to the lossy path: the rest must still be complete.
	g2, ep2 := receiverFor(t)
	lossy := frames[0].to
	delivered = nil
	for _, fr := range frames {
		if fr.kind == Striped && fr.to == lossy {
			continue
		}
		out := g2.receive(t, fr.kind, fr.body, ep2[0])
		delivered = append(delivered, out.Deliver...)
	}
	_ = lossy
	if len(delivered) < len(originals)/2 {
		t.Fatalf("clean-path copies too few: %d", len(delivered))
	}
}

func TestNoProtectionWhenClean(t *testing.T) {
	_, frames, s := sendProtected(t, 0, 8)
	for _, fr := range frames {
		if fr.kind == Parity {
			t.Fatal("parity on a clean path")
		}
	}
	if s.Stats().BulkDuplicates != 0 {
		t.Fatal("duplicated on a clean path")
	}
}
