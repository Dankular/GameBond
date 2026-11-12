package lan

import (
	"bytes"
	"testing"
	"time"

	"gamebond.local/nativeedge/iec62439"
)

var (
	rbMAC   = [6]byte{2, 0, 0, 0, 0, 1}
	peerMAC = [6]byte{2, 0, 0, 0, 0, 2}
)

func frameFrom(src [6]byte, n int) []byte {
	f := append([]byte{}, rbMAC[:]...)
	f = append(f, src[:]...)
	f = append(f, 0x08, 0x00)
	return append(f, bytes.Repeat([]byte{7}, n)...)
}

func newRB(t *testing.T) (rb *RedBox, farA, farB *MemoryIO) {
	nearA, farA := MemoryPair(rbMAC, peerMAC)
	nearB, farB := MemoryPair(rbMAC, peerMAC)
	rb = NewRedBox(nearA, nearB, nil)
	t.Cleanup(func() { rb.Close() })
	return rb, farA, farB
}

func TestRedBoxWritesBothLANsWithSameSequence(t *testing.T) {
	rb, farA, farB := newRB(t)
	if err := rb.Write(frameFrom(rbMAC, 80)); err != nil {
		t.Fatal(err)
	}
	fa, _ := farA.Read(time.Second)
	fb, _ := farB.Read(time.Second)
	ra, oka := iec62439.ParseRCT(fa)
	rbct, okb := iec62439.ParseRCT(fb)
	if !oka || !okb || ra.Lan != iec62439.LANA || rbct.Lan != iec62439.LANB || ra.Seq != rbct.Seq {
		t.Fatalf("A %+v %v B %+v %v", ra, oka, rbct, okb)
	}
}

func TestRedBoxDeliversOnceAndSurvivesOneLANDown(t *testing.T) {
	rb, farA, farB := newRB(t)
	for i := 0; i < 20; i++ {
		f := frameFrom(peerMAC, 60+i)
		a, _ := iec62439.AppendRCT(f, uint16(i), iec62439.LANA)
		b, _ := iec62439.AppendRCT(f, uint16(i), iec62439.LANB)
		if i < 10 { // LAN A dies after ten frames
			farA.Write(a)
		}
		farB.Write(b)
	}
	got := 0
	for {
		f, err := rb.Read(200 * time.Millisecond)
		if err != nil || f == nil {
			break
		}
		if bytes.Equal(f[6:12], peerMAC[:]) {
			got++
		}
	}
	if got != 20 {
		t.Fatalf("delivered %d of 20", got)
	}
	if st := rb.Stats(); st.DuplicatesDropped != 10 {
		t.Fatalf("%+v", st)
	}
}

func TestRedBoxSupervisionIsConsumedAndReportsDeadLAN(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	nearA, farA := MemoryPair(rbMAC, peerMAC)
	nearB, farB := MemoryPair(rbMAC, peerMAC)
	rb := NewRedBox(nearA, nearB, clock)
	defer rb.Close()
	peer := &iec62439.Supervisor{MAC: peerMAC}
	for i := 0; i < 6; i++ {
		a, b := peer.Due(now)
		if a != nil {
			farA.Write(a)
			if i < 2 {
				farB.Write(b)
			}
		}
		if f, _ := rb.Read(50 * time.Millisecond); f != nil {
			t.Fatal("supervision frame reached the gateway")
		}
		now = now.Add(2 * time.Second)
	}
	if st := rb.Stats(); st.SupervisionReceived == 0 || st.SupervisionSent == 0 {
		t.Fatalf("%+v", st)
	}
	downA, downB := rb.LANDown(peerMAC)
	if downA || !downB {
		t.Fatalf("A down %v B down %v", downA, downB)
	}
}

func TestRedBoxPassesPlainFramesAndDropsOwnEcho(t *testing.T) {
	rb, farA, _ := newRB(t)
	farA.Write(frameFrom(peerMAC, 70))
	farA.Write(frameFrom(rbMAC, 70)) // an echo of our own frame
	f, _ := rb.Read(time.Second)
	if f == nil || !bytes.Equal(f[6:12], peerMAC[:]) {
		t.Fatal("plain frame not passed")
	}
	if g, _ := rb.Read(100 * time.Millisecond); g != nil {
		t.Fatal("own frame passed")
	}
	if st := rb.Stats(); st.NoRCT != 1 || st.OwnFramesDropped != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestHSRRedBoxTagsBothWaysAndDeliversOnce(t *testing.T) {
	nearA, farA := MemoryPair(rbMAC, peerMAC)
	nearB, farB := MemoryPair(rbMAC, peerMAC)
	rb := NewHSRRedBox(nearA, nearB, nil)
	t.Cleanup(func() { rb.Close() })
	if err := rb.Write(frameFrom(rbMAC, 80)); err != nil {
		t.Fatal(err)
	}
	fa, _ := farA.Read(time.Second)
	fb, _ := farB.Read(time.Second)
	ta, oka := iec62439.ParseHSRTag(fa)
	tb, okb := iec62439.ParseHSRTag(fb)
	if !oka || !okb || ta.Path != iec62439.LANA || tb.Path != iec62439.LANB || ta.Seq != tb.Seq {
		t.Fatalf("tags %+v %+v %v %v", ta, tb, oka, okb)
	}
	// A frame for the gateway arrives round both sides of the ring: delivered once.
	in := frameFrom(peerMAC, 80)
	toUs := append(append([]byte{}, rbMAC[:]...), in[6:]...)
	ga, _ := iec62439.AddHSRTag(toUs, iec62439.LANA, 9)
	gb, _ := iec62439.AddHSRTag(toUs, iec62439.LANB, 9)
	farA.Write(ga)
	farB.Write(gb)
	got, _ := rb.Read(time.Second)
	if got == nil || !bytes.Equal(got[:6], rbMAC[:]) {
		t.Fatal("frame for the gateway not delivered")
	}
	if again, _ := rb.Read(200 * time.Millisecond); again != nil {
		t.Fatal("ring duplicate delivered twice")
	}
	if c := rb.Stats(); c.DuplicatesDropped != 1 || c.Forwarded != 0 {
		t.Fatalf("%+v", c)
	}
	// A frame for another node is forwarded to the opposite port, not delivered.
	other := append([]byte{2, 0, 0, 0, 0, 9}, in[6:]...)
	of, _ := iec62439.AddHSRTag(other, iec62439.LANA, 10)
	farA.Write(of)
	if d, _ := rb.Read(300 * time.Millisecond); d != nil {
		t.Fatal("transit frame delivered to the gateway")
	}
	var fw []byte
	for i := 0; i < 4; i++ { // skip supervision the box sent meanwhile
		fw, _ = farB.Read(time.Second)
		if bytes.Equal(fw, of) {
			break
		}
	}
	if fw == nil || !bytes.Equal(fw, of) {
		t.Fatalf("transit frame not forwarded unchanged: got %d bytes want %d, stats %+v", len(fw), len(of), rb.Stats())
	}
}
