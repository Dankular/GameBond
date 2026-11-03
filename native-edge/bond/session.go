package bond

import (
	"net/netip"
	"time"
)

type SessionOptions struct {
	MTU                      int
	ClientIP                 netip.Addr
	InitialRate, MaximumRate float64
	ReorderTimeout           time.Duration
	Policies                 map[byte]QueuePolicy
	GamePorts                []uint16
	QoS                      QoSSettings
	Redundant                bool
}

func DefaultSessionOptions() SessionOptions {
	return SessionOptions{MTU: 1280, ClientIP: netip.MustParseAddr("10.77.0.2"), InitialRate: 1, MaximumRate: 100, ReorderTimeout: 30 * time.Millisecond, QoS: DefaultQoSSettings()}
}

type SessionStats struct{ Malformed, IPv6Unsupported, MTUDrops, WrongSource, WrongDestination, OutboundPackets, OutboundBytes, InboundPackets, InboundBytes uint64 }
type Session struct {
	Receiver   *Receiver
	Sender     *Sender
	Transmit   *TransmitQueue
	Inject     *InjectionQueue
	classifier *Classifier
	qos        *AdaptiveQoS
	options    SessionOptions
	stats      SessionStats
	peer       [16]byte
	hasPeer    bool
}

func NewSession(key, session []byte, options SessionOptions) (*Session, error) {
	if options.MTU < 576 || options.MTU > 9000 || !options.ClientIP.Is4() {
		return nil, ErrFrame
	}
	codec, err := NewCodec(key, session, "server")
	if err != nil {
		return nil, err
	}
	r, err := NewReceiver(codec, options.MTU+Overhead+24)
	if err != nil {
		return nil, err
	}
	if err = r.SetReorderTimeout(options.ReorderTimeout); err != nil {
		return nil, err
	}
	sender, err := NewSender(r, options.InitialRate, options.MaximumRate)
	if err != nil {
		return nil, err
	}
	classifier, err := NewClassifier(options.Policies, options.GamePorts, options.QoS)
	if err != nil {
		return nil, err
	}
	qos, err := NewAdaptiveQoS(options.QoS)
	if err != nil {
		return nil, err
	}
	transmit, _ := NewTransmitQueue(sender, 1024, 4*1024*1024)
	transmit.SetQoS(qos)
	inject, _ := NewInjectionQueue(1024, 4*1024*1024)
	return &Session{Receiver: r, Sender: sender, Transmit: transmit, Inject: inject, classifier: classifier, qos: qos, options: options}, nil
}
func (s *Session) syncPeer() {
	if s.Receiver.handshake.hasPeer && (!s.hasPeer || s.peer != s.Receiver.handshake.peer) {
		s.peer = s.Receiver.handshake.peer
		s.hasPeer = true
		s.Transmit.syncPeer()
		s.Inject.Reset()
		s.classifier.Reset()
		s.qos.previous = make(map[*receivePath]qualityCounters)
		s.qos.quality = nil
		s.qos.last = time.Time{}
		clear(s.qos.until)
		clear(s.qos.reasons)
	}
}
func (s *Session) classify(packet []byte, incoming bool, now time.Time) (Classification, bool) {
	if len(packet) > s.options.MTU {
		s.stats.MTUDrops++
		return Classification{}, false
	}
	if len(packet) > 0 && packet[0]>>4 == 6 {
		s.stats.IPv6Unsupported++
		return Classification{}, false
	}
	p, err := ParseIPv4(packet)
	if err != nil {
		s.stats.Malformed++
		return Classification{}, false
	}
	client := s.options.ClientIP.As4()
	if incoming && p.Source != client {
		s.stats.WrongSource++
		return Classification{}, false
	}
	if !incoming && p.Destination != client {
		s.stats.WrongDestination++
		return Classification{}, false
	}
	return s.classifier.Classify(p, now), true
}
func queued(packet []byte, c Classification, now time.Time) QueuedPacket {
	return QueuedPacket{Payload: packet, Flow: c.Info.Flow, Priority: c.Policy.Priority, Replicate: c.Policy.Replicate, Expires: now.Add(time.Duration(c.Policy.MaxAgeMS * float64(time.Millisecond))), Tag: c.Tag, ClassCapacity: c.Policy.Capacity}
}
func (s *Session) process(result ReceiveResult, now time.Time, writer DatagramWriter) {
	s.syncPeer()
	s.Sender.Controls(result, now, writer)
	for _, packet := range result.Deliver {
		if c, ok := s.classify(packet, true, now); ok {
			s.stats.InboundPackets++
			s.stats.InboundBytes += uint64(len(packet))
			s.Inject.Enqueue(queued(packet, c, now))
		}
	}
}
func (s *Session) UDP(frame []byte, endpoint netip.AddrPort, now time.Time, writer DatagramWriter) error {
	result, err := s.Receiver.Receive(frame, endpoint, now)
	if err != nil {
		return err
	}
	s.process(result, now, writer)
	return nil
}
func (s *Session) TUN(packet []byte, now time.Time) bool {
	s.syncPeer()
	c, ok := s.classify(packet, false, now)
	if !ok {
		return false
	}
	s.stats.OutboundPackets++
	s.stats.OutboundBytes += uint64(len(packet))
	p := queued(packet, c, now)
	if s.options.Redundant {
		p.Replicate = true
	}
	return s.Transmit.Enqueue(p)
}
func (s *Session) Pump(now time.Time, writer DatagramWriter, inject func([]byte) error) (time.Time, error) {
	result, err := s.Receiver.Tick(now)
	if err != nil {
		return now, err
	}
	s.process(result, now, writer)
	if err = s.Sender.Maintenance(now, writer); err != nil {
		return now, err
	}
	due, err := s.Transmit.Pump(now, writer)
	if err != nil {
		return due, err
	}
	if err = s.Inject.Drain(now, inject); err != nil {
		return due, err
	}
	return due, nil
}
func (s *Session) Stats(now time.Time) map[string]any {
	return map[string]any{"backend": "native_go", "packets": s.stats, "transport": map[string]any{"receive": s.Receiver.Stats(), "send": s.Sender.Stats(), "paths": s.Sender.Paths(now), "reorder": s.Receiver.ReorderStats()}, "queues": map[string]any{"transmit": s.Transmit.Stats(), "inject": s.Inject.Stats()}, "qos": s.qos.Stats(now), "profile_cache_entries": len(s.classifier.flows), "fragment_cache_entries": len(s.classifier.fragments)}
}
