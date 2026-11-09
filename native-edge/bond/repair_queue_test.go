package bond

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func tcpPacket(payload string) []byte {
	p := make([]byte, 40+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[9] = 6
	copy(p[12:16], []byte{10, 77, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:], 1234)
	binary.BigEndian.PutUint16(p[22:], 443)
	p[32] = 0x50
	p[33] = 0x10
	copy(p[40:], payload)
	return p
}
func TestRepairRetainsFlowSequenceUsesFreshNonceAndStopsAfterTwo(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	var frames []Datagram
	writer := func(d Datagram) error { frames = append(frames, d); return nil }
	payload := tcpPacket("application data")
	sent, _, err := s.Bulk(payload, "tcp-flow", f.now, writer)
	if !sent || err != nil {
		t.Fatal(err)
	}
	original, _ := f.c.Decode(frames[0].Frame)
	request := append([]byte(nil), original.Payload[:16]...)
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(20 * time.Millisecond)
		out := f.receive(t, Repair, request, a[0])
		s.Controls(out, f.now, writer)
		if err := s.Maintenance(f.now, writer); err != nil {
			t.Fatal(err)
		}
	}
	if len(frames) != 3 || s.Stats().RepairCopies != 2 || s.Stats().Copies != 3 || s.Stats().PayloadPackets != 1 {
		t.Fatal("repair attempts or payload accounting differ", s.Stats(), len(frames))
	}
	for _, d := range frames[1:] {
		packet, err := f.c.Decode(d.Frame)
		if err != nil || packet.Header.Sequence <= original.Header.Sequence || !bytes.Equal(packet.Payload[:16], original.Payload[:16]) || !bytes.Equal(packet.Payload[24:], payload) {
			t.Fatal("repair reused nonce or changed inner packet", err)
		}
	}
	s.Maintenance(f.now.Add(time.Second), writer)
	if len(s.repairs) != 0 {
		t.Fatal("repair cache did not expire")
	}
}
func TestReceiveHolesRequestBoundedTCPRepairsWithoutBlockingUrgent(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	f.r.reorder.config.Timeout = 200 * time.Millisecond
	f.receive(t, Striped, stripe(77, 1, 1, tcpPacket("later")), a[0])
	var requests []Packet
	writer := func(d Datagram) error {
		packet, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, packet)
		return nil
	}
	for _, at := range []time.Duration{16, 60, 110} {
		if err := s.Maintenance(f.now.Add(at*time.Millisecond), writer); err != nil {
			t.Fatal(err)
		}
	}
	if len(requests) != 2 {
		t.Fatal("missing TCP range not bounded to two repair attempts", len(requests))
	}
	for _, p := range requests {
		if p.Header.Kind != Repair || binary.BigEndian.Uint64(p.Payload) != 77 || binary.BigEndian.Uint64(p.Payload[8:]) != 0 {
			t.Fatal("wrong repair hole")
		}
	}
	out := f.receive(t, Data, []byte("urgent"), a[0])
	if len(out.Deliver) != 1 {
		t.Fatal("repair hole blocked urgent DATA")
	}
	// UDP/game packets never trigger this TCP repair mechanism.
	f.receive(t, Striped, stripe(88, 1, 1, []byte("not TCP")), a[0])
	s.Maintenance(f.now.Add(150*time.Millisecond), writer)
	if len(requests) != 2 {
		t.Fatal("UDP was retransmitted as TCP")
	}
}
func TestTransmitQueueAdmitsUrgentDuringBulkPressureAndOwnsBuffers(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 2, 2800)
	expires := f.now.Add(200 * time.Millisecond)
	for i := 0; i < 2; i++ {
		if !q.Enqueue(QueuedPacket{Payload: []byte("bulk"), Flow: "b", Expires: expires}) {
			t.Fatal("bulk admission failed")
		}
	}
	ack := tcpPacket("")
	if !q.Enqueue(QueuedPacket{Payload: ack, Flow: "a", Expires: expires}) {
		t.Fatal("TCP ACK was not admitted over full bulk")
	}
	ack[20] ^= 1
	for i := 0; i < maxPending; i++ {
		s.r.paths[pk(a[0])].budget.Sent(uint64(i), 1400, 0)
	}
	var delivered [][]byte
	writer := func(d Datagram) error {
		packet, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Header.Kind == Data {
			delivered = append(delivered, packet.Payload)
		}
		return nil
	}
	q.Pump(f.now, writer)
	if len(delivered) != 1 || !bytes.Equal(delivered[0], tcpPacket("")) || q.Stats().EvictedBulk != 1 || q.Stats().QueuedPackets != 1 {
		t.Fatal("bulk pressure blocked ACK or queue borrowed memory", q.Stats())
	}
	q.Pump(expires, writer)
	if q.Stats().Expired != 1 || q.Stats().QueuedPackets != 0 || q.Stats().QueuedBytes != 0 {
		t.Fatal("expired bulk retained", q.Stats())
	}
}
func TestMalformedTCPAndFragmentsCannotBypassBulk(t *testing.T) {
	valid := tcpPacket("")
	if !IsTCPControl(valid) {
		t.Fatal("valid ACK not recognized")
	}
	withData := tcpPacket("data")
	if IsTCPControl(withData) {
		t.Fatal("TCP application bytes promoted to control")
	}
	fragment := append([]byte(nil), valid...)
	fragment[6] = 0x20
	invalidLength := append([]byte(nil), valid...)
	invalidLength[3]--
	invalidTCPHeader := append([]byte(nil), valid...)
	invalidTCPHeader[32] = 0x10
	for _, p := range [][]byte{fragment, invalidLength, invalidTCPHeader, valid[:30]} {
		if IsTCPControl(p) {
			t.Fatal("malformed/fragmented packet bypassed bulk")
		}
	}
}
func TestPeerRestartDiscardsOldQueuedPlaintextAndRepairState(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 4, 4096)
	if !q.Enqueue(QueuedPacket{Payload: tcpPacket("old session"), Flow: "old", Expires: f.now.Add(time.Second)}) {
		t.Fatal("admission failed")
	}
	client, _ := NewCodec(f.c.key[:], f.c.Session[:], "client")
	f.c = client
	f.connect(t, a[0])
	if !q.Enqueue(QueuedPacket{Payload: tcpPacket("new session"), Flow: "new", Expires: f.now.Add(time.Second)}) {
		t.Fatal("new admission failed")
	}
	var payloads [][]byte
	q.Pump(f.now, func(d Datagram) error {
		p, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, p.Payload[24:])
		return nil
	})
	if len(payloads) != 1 || !bytes.Equal(payloads[0], tcpPacket("new session")) || q.Stats().PeerResetDropped != 1 {
		t.Fatal("old session crossed peer restart", q.Stats())
	}
}
