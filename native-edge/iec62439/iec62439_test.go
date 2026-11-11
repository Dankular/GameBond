package iec62439

import (
	"bytes"
	"testing"
	"time"
)

func ethFrame(n int) []byte {
	f := []byte{1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 0x08, 0x00}
	for i := 0; i < n; i++ {
		f = append(f, byte(i))
	}
	return f
}

func TestRCTRoundTripAndPadding(t *testing.T) {
	for _, n := range []int{0, 10, 46, 100, 1400} {
		orig := ethFrame(n)
		a, err := AppendRCT(orig, 77, LANA)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := AppendRCT(orig, 77, LANB)
		if len(a) < minFrame+RCTSize || len(a) != len(b) {
			t.Fatalf("n=%d len %d", n, len(a))
		}
		ra, ok := ParseRCT(a)
		rb, _ := ParseRCT(b)
		if !ok || ra.Seq != 77 || ra.Lan != LANA || rb.Lan != LANB || int(ra.LSDU) != len(a)-14 {
			t.Fatalf("n=%d parsed %+v %+v", n, ra, rb)
		}
		got, _, ok := StripRCT(a)
		if !ok || !bytes.HasPrefix(got, orig) {
			t.Fatalf("n=%d strip failed", n)
		}
	}
}

func TestRCTRejectsWrongSizeAndSuffix(t *testing.T) {
	a, _ := AppendRCT(ethFrame(100), 1, LANA)
	if _, ok := ParseRCT(a[:len(a)-1]); ok {
		t.Fatal("truncated frame accepted")
	}
	a[len(a)-1] ^= 1
	if _, ok := ParseRCT(a); ok {
		t.Fatal("bad suffix accepted")
	}
	if _, err := AppendRCT(ethFrame(5000), 1, LANA); err != ErrSize {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := AppendRCT(ethFrame(5), 1, 3); err != ErrLAN {
		t.Fatal("bad lan")
	}
}

func TestRCTVLANSize(t *testing.T) {
	f := []byte{1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 0x81, 0x00, 0, 5, 0x08, 0x00}
	f = append(f, make([]byte, 20)...)
	a, err := AppendRCT(f, 9, LANB)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := ParseRCT(a)
	if !ok || int(r.LSDU) != len(a)-18 {
		t.Fatalf("%+v %v", r, ok)
	}
}

func TestHSRTagRoundTrip(t *testing.T) {
	orig := ethFrame(100)
	h, err := AddHSRTag(orig, 1, 500)
	if err != nil {
		t.Fatal(err)
	}
	tag, ok := ParseHSRTag(h)
	if !ok || tag.Path != 1 || tag.Seq != 500 || tag.Encap != 0x0800 || len(h) != len(orig)+HSRTagSize {
		t.Fatalf("%+v %v len %d", tag, ok, len(h))
	}
	got, _, ok := StripHSRTag(h)
	if !ok || !bytes.Equal(got, orig) {
		t.Fatal("strip did not restore the frame")
	}
	short, _ := AddHSRTag(ethFrame(0), 0, 1)
	if len(short) != minFrame+HSRTagSize {
		t.Fatalf("short frame len %d", len(short))
	}
}

func TestSupervisionRoundTrip(t *testing.T) {
	src := [6]byte{0xaa, 1, 2, 3, 4, 5}
	rb := [6]byte{9, 8, 7, 6, 5, 4}
	f := BuildSupervision(src, Supervision{Version: 1, Seq: 42, Type: TLVPRPDD, Node: src, RedBox: &rb})
	if len(f) < minFrame {
		t.Fatal("not padded")
	}
	s, ok := ParseSupervision(f)
	if !ok || s.Seq != 42 || s.Type != TLVPRPDD || s.Node != src || s.RedBox == nil || *s.RedBox != rb || s.Version != 1 {
		t.Fatalf("%+v %v", s, ok)
	}
	withRCT, _ := AppendRCT(f, 3, LANA)
	if _, ok := ParseSupervision(withRCT); !ok {
		t.Fatal("RCT broke parsing")
	}
	if _, ok := ParseSupervision(ethFrame(60)); ok {
		t.Fatal("ordinary frame parsed as supervision")
	}
}

func TestDiscardDropsSecondCopyOnly(t *testing.T) {
	d := NewDiscard()
	src := [6]byte{1}
	now := time.Now()
	for seq := uint16(65500); seq != 100; seq++ { // wraps through zero
		if !d.Accept(src, seq, now) {
			t.Fatalf("first copy of %d dropped", seq)
		}
		if d.Accept(src, seq, now.Add(time.Millisecond)) {
			t.Fatalf("second copy of %d passed", seq)
		}
	}
	if !d.Accept([6]byte{2}, 5, now) {
		t.Fatal("other source shares state")
	}
}

func TestDiscardForgetsAfterEntryTime(t *testing.T) {
	d := NewDiscard()
	src := [6]byte{1}
	now := time.Now()
	d.Accept(src, 7, now)
	if d.Accept(src, 7, now.Add(300*time.Millisecond)) {
		t.Fatal("duplicate inside window passed")
	}
	if !d.Accept(src, 7, now.Add(time.Second)) {
		t.Fatal("entry not forgotten")
	}
	if d.Forget(now.Add(2*time.Minute)) != 1 {
		t.Fatal("node not forgotten")
	}
}

func TestDiscardBoundsMemory(t *testing.T) {
	d := NewDiscard()
	src := [6]byte{1}
	now := time.Now()
	for i := 0; i < 1000; i++ {
		d.Accept(src, uint16(i*blockSeqs), now)
	}
	if n := len(d.nodes[src].blocks); n > maxBlocks {
		t.Fatalf("%d blocks", n)
	}
}

func TestSupervisorAndNodeTable(t *testing.T) {
	mac := [6]byte{0xaa, 1, 2, 3, 4, 5}
	s := &Supervisor{MAC: mac}
	nodes := NewNodes()
	now := time.Now()
	sent := 0
	for i := 0; i < 20; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		a, b := s.Due(at)
		if a == nil {
			continue
		}
		sent++
		ra, _ := ParseRCT(a)
		rb, _ := ParseRCT(b)
		if ra.Lan != LANA || rb.Lan != LANB || ra.Seq != rb.Seq {
			t.Fatal("copies differ")
		}
		sa, ok := ParseSupervision(a)
		if !ok || sa.Node != mac {
			t.Fatal("unparsable")
		}
		nodes.Supervision(sa, LANA, at)
		if i < 8 { // LAN B dies after 8 s
			nodes.Supervision(sa, LANB, at)
		}
	}
	if sent != 10 {
		t.Fatalf("sent %d supervision frames in 20 s", sent)
	}
	downA, downB := nodes.LANDown(mac, now.Add(19*time.Second))
	if downA || !downB {
		t.Fatalf("down A=%v B=%v", downA, downB)
	}
	if nodes.Forget(now.Add(19*time.Second)) != 0 || nodes.Forget(now.Add(200*time.Second)) != 1 {
		t.Fatal("forget timing")
	}
}
