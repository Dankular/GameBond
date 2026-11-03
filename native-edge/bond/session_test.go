package bond

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func sessionFixture(t *testing.T) (receiverFixture, *Session, DatagramWriter) {
	t.Helper()
	f := newReceiverFixture(t)
	options := DefaultSessionOptions()
	options.InitialRate = 10
	s, err := NewSession(f.c.key[:], f.c.Session[:], options)
	if err != nil {
		t.Fatal(err)
	}
	var replies []Datagram
	writer := func(d Datagram) error { replies = append(replies, d); return nil }
	frame, _ := f.c.Encode(Hello, bytes.Repeat([]byte{4}, 16))
	if err = s.UDP(frame, f.endpoint, f.now, writer); err != nil {
		t.Fatal(err)
	}
	challenge, _ := f.c.Decode(replies[len(replies)-1].Frame)
	frame, _ = f.c.Encode(Reset, challenge.Payload)
	if err = s.UDP(frame, f.endpoint, f.now, writer); err != nil {
		t.Fatal(err)
	}
	return f, s, writer
}
func TestSessionValidatesTunnelAddressesBeforeLearningOrInjecting(t *testing.T) {
	f, s, writer := sessionFixture(t)
	packet := udpPacket(1234, 443, 46)
	packet[12] = 11
	frame, _ := f.c.Encode(Data, packet)
	s.UDP(frame, f.endpoint, f.now, writer)
	if s.Inject.Stats().QueuedPackets != 0 || len(s.classifier.flows) != 0 || s.stats.WrongSource != 1 {
		t.Fatal("spoofed source affected state")
	}
	packet = udpPacket(1234, 443, 46)
	if s.TUN(packet, f.now) || len(s.classifier.flows) != 0 || s.stats.WrongDestination != 1 {
		t.Fatal("wrong tunnel destination affected profile state")
	}
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	s.TUN(ipv6, f.now)
	if s.stats.IPv6Unsupported != 1 {
		t.Fatal("IPv6 silently accepted")
	}
}
func TestSessionLearnsReturnQoSAndCountsActualDeviceWrites(t *testing.T) {
	f, s, writer := sessionFixture(t)
	packet := udpPacket(1234, 443, 26)
	frame, _ := f.c.Encode(Data, packet)
	s.UDP(frame, f.endpoint, f.now, writer)
	if s.Inject.Stats().QueuedPackets != 1 {
		t.Fatal("valid packet not admitted")
	}
	if err := s.Inject.Drain(f.now, func([]byte) error { return ErrWouldBlock }); err != nil || s.Inject.Stats().Written != 0 {
		t.Fatal("blocked write counted as delivered")
	}
	s.Inject.Drain(f.now, func(p []byte) error {
		if !bytes.Equal(p, packet) {
			t.Fatal("packet changed")
		}
		return nil
	})
	if s.Inject.Stats().WrittenBytes != uint64(len(packet)) {
		t.Fatal("actual application write count missing")
	}
	reverse := reverseUDP(packet)
	reverse[1] = 0
	if !s.TUN(reverse, f.now) {
		t.Fatal("return packet not accepted")
	}
	queued := s.Transmit.priority.Front().Value.(QueuedPacket)
	if queued.Tag != 26 || !queued.Priority || queued.Replicate {
		t.Fatal("return call profile lost")
	}
}
func TestInjectionBackpressureAdmitsControlAndExpiredPacketsDoNotLeak(t *testing.T) {
	now := time.Now()
	q, _ := NewInjectionQueue(2, 2800)
	for i := 0; i < 2; i++ {
		q.Enqueue(QueuedPacket{Payload: tcpPacket("bulk"), ClassCapacity: 2, Expires: now.Add(time.Second)})
	}
	if !q.Enqueue(QueuedPacket{Payload: tcpPacket(""), ClassCapacity: 2, Expires: now.Add(20 * time.Millisecond)}) {
		t.Fatal("full bulk class rejected ACK")
	}
	writes := 0
	q.Drain(now, func(p []byte) error {
		writes++
		if !IsTCPControl(p) {
			return ErrWouldBlock
		}
		return nil
	})
	if writes != 2 || q.Stats().Written != 1 || q.Stats().QueuedPackets != 1 {
		t.Fatal("priority injection not serviced first", q.Stats())
	}
	q.Drain(now.Add(2*time.Second), func([]byte) error { return errors.New("expired packet reached device") })
	if q.Stats().Expired != 1 {
		t.Fatal("expired packet not retired")
	}
}
func TestReorderConfigurationSurvivesAuthenticatedPeerRestart(t *testing.T) {
	f := newReceiverFixture(t)
	if err := f.r.SetReorderTimeout(75 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	f.connect(t, netip.MustParseAddrPort("127.0.0.1:1234"))
	if f.r.reorder.config.Timeout != 75*time.Millisecond {
		t.Fatal("peer adoption reset configured reorder timeout")
	}
}
