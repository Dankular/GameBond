package iec62439

import "encoding/binary"

// Supervision TLV types.
const (
	TLVEnd         = 0
	TLVPRPDD       = 20 // duplicate discard node
	TLVPRPDA       = 21 // duplicate accept node
	TLVRedBox      = 30
	TLVHSRAnnounce = 22
	TLVHSRLife     = 23
)

// Timing from the standard.
const (
	LifeCheckInterval = 2 * 1e9   // ns
	NodeForgetTime    = 60 * 1e9  // ns
	EntryForgetTime   = 400 * 1e6 // ns
	HSRAnnounce       = 100 * 1e6 // ns
)

// SupervisionMAC is the multicast destination of supervision frames.
var SupervisionMAC = [6]byte{0x01, 0x15, 0x4e, 0x00, 0x01, 0x00}

// Supervision is the decoded payload of a supervision frame.
type Supervision struct {
	Version uint8
	Path    uint8
	Seq     uint16
	Type    uint8   // first TLV type
	Node    [6]byte // MAC address carried by the first TLV
	RedBox  *[6]byte
}

// BuildSupervision returns a PRP supervision frame (no RCT; add one with AppendRCT).
// The payload is the supervision tag (path/version, sequence), the node TLV and the
// terminating TLV, padded to the Ethernet minimum.
func BuildSupervision(src [6]byte, sup Supervision) []byte {
	f := make([]byte, 0, minFrame)
	f = append(f, SupervisionMAC[:]...)
	f = append(f, src[:]...)
	f = binary.BigEndian.AppendUint16(f, EtherTypePRP)
	f = binary.BigEndian.AppendUint16(f, uint16(sup.Path&0xF)<<12|uint16(sup.Version))
	f = binary.BigEndian.AppendUint16(f, sup.Seq)
	f = append(f, sup.Type, 6)
	f = append(f, sup.Node[:]...)
	if sup.RedBox != nil {
		f = append(f, TLVRedBox, 6)
		f = append(f, sup.RedBox[:]...)
	}
	f = append(f, TLVEnd, 0)
	for len(f) < minFrame {
		f = append(f, 0)
	}
	return f
}

// ParseSupervision decodes a supervision frame, which may still carry an RCT.
func ParseSupervision(frame []byte) (Supervision, bool) {
	if len(frame) < ethHeader+6+2+6 || [6]byte(frame[:6]) != SupervisionMAC ||
		binary.BigEndian.Uint16(frame[12:]) != EtherTypePRP {
		return Supervision{}, false
	}
	b := frame[ethHeader:]
	v := binary.BigEndian.Uint16(b)
	s := Supervision{Path: uint8(v >> 12), Version: uint8(v & 0xFFF), Seq: binary.BigEndian.Uint16(b[2:])}
	b = b[4:]
	first := true
	for len(b) >= 2 {
		typ, n := b[0], int(b[1])
		if typ == TLVEnd {
			break
		}
		if n != 6 || len(b) < 2+n {
			return Supervision{}, false
		}
		var mac [6]byte
		copy(mac[:], b[2:8])
		switch {
		case first:
			s.Type, s.Node, first = typ, mac, false
		case typ == TLVRedBox:
			m := mac
			s.RedBox = &m
		}
		b = b[2+n:]
	}
	if first {
		return Supervision{}, false
	}
	return s, true
}
