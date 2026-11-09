package stackio

import (
	"bytes"
	"testing"
)

func TestRoundTripAndRejections(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	pkt := bytes.Repeat([]byte{1}, 1280)
	big := bytes.Repeat([]byte{2}, 3000)
	if err := w.Write(KindPacket, pkt); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(KindStackEvent, big); err != nil { // control JSON may exceed the MTU
		t.Fatal(err)
	}
	if w.Write(KindPacket, make([]byte, 1281)) == nil || w.Write(KindPacket, nil) == nil {
		t.Fatal("invalid frame written")
	}
	for _, want := range [][]byte{pkt, big} {
		f, err := Read(&b)
		if err != nil || !bytes.Equal(f.Payload, want) {
			t.Fatalf("frame mismatch %v", err)
		}
	}
	// Wire bytes must equal Python's struct.pack('!BH').
	b.Reset()
	NewWriter(&b).Write(3, []byte("x"))
	if !bytes.Equal(b.Bytes(), []byte{3, 0, 1, 'x'}) {
		t.Fatalf("wire %x", b.Bytes())
	}
	for _, bad := range [][]byte{{0, 0, 0}, {0, 5, 0, 1}, {2}} {
		if _, err := Read(bytes.NewReader(bad)); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}
