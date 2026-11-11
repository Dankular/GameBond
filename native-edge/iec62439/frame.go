// Package iec62439 implements the frame formats and receive-side rules of IEC 62439-3
// (Parallel Redundancy Protocol and High-availability Seamless Redundancy): the PRP
// Redundancy Control Trailer, the HSR tag, supervision frames and duplicate discard.
//
// The formats follow the standard as implemented by the Linux net/hsr code, which was
// used as a cross-check (the standard itself is not freely available). Nothing here
// claims certification: that needs interoperability testing against certified
// equipment.
package iec62439

import (
	"encoding/binary"
	"errors"
)

const (
	// EtherTypePRP is both the PRP RCT suffix and the supervision frame EtherType.
	EtherTypePRP uint16 = 0x88FB
	// EtherTypeHSR is the HSR (version 1) tag EtherType.
	EtherTypeHSR  uint16 = 0x892F
	etherTypeVLAN uint16 = 0x8100

	RCTSize    = 6
	HSRTagSize = 6

	// LANA and LANB are the LanId values of the RCT: 0b1010 and 0b1011.
	LANA uint8 = 0xA
	LANB uint8 = 0xB

	ethHeader  = 14
	vlanHeader = 4
	minFrame   = 60 // minimum Ethernet frame without FCS
	maxLSDU    = 0x0FFF
)

var (
	ErrShort  = errors.New("iec62439: frame too short")
	ErrLAN    = errors.New("iec62439: LanId must be LANA or LANB")
	ErrSize   = errors.New("iec62439: frame too large for a 12-bit LSDU size")
	ErrVLAN   = errors.New("iec62439: VLAN-tagged frames are not supported with the HSR tag")
	ErrFormat = errors.New("iec62439: malformed frame")
)

// RCT is the 6-byte PRP Redundancy Control Trailer appended after the payload:
// sequence number, 4-bit LanId with 12-bit LSDU size, and the 0x88FB suffix.
type RCT struct {
	Seq  uint16
	Lan  uint8  // LANA or LANB
	LSDU uint16 // frame length after the Ethernet header (and VLAN tag), RCT included
}

func vlanTagged(frame []byte) bool {
	return len(frame) >= ethHeader && binary.BigEndian.Uint16(frame[12:]) == etherTypeVLAN
}

// payloadStart is the offset past the Ethernet header and any VLAN tag.
func lsduSize(frame []byte) int {
	n := len(frame) - ethHeader
	if vlanTagged(frame) {
		n -= vlanHeader
	}
	return n
}

// AppendRCT returns a copy of the Ethernet frame (no FCS) padded to the minimum size
// and followed by a trailer for the given LAN. Both copies of a frame carry the same
// sequence number and differ only in the LanId.
func AppendRCT(frame []byte, seq uint16, lan uint8) ([]byte, error) {
	if lan != LANA && lan != LANB {
		return nil, ErrLAN
	}
	if len(frame) < ethHeader {
		return nil, ErrShort
	}
	size := minFrame
	if vlanTagged(frame) {
		size += vlanHeader
	}
	out := append([]byte(nil), frame...)
	for len(out) < size {
		out = append(out, 0)
	}
	out = append(out, 0, 0, 0, 0, 0, 0)
	lsdu := lsduSize(out)
	if lsdu > maxLSDU {
		return nil, ErrSize
	}
	t := out[len(out)-RCTSize:]
	binary.BigEndian.PutUint16(t, seq)
	binary.BigEndian.PutUint16(t[2:], uint16(lan)<<12|uint16(lsdu))
	binary.BigEndian.PutUint16(t[4:], EtherTypePRP)
	return out, nil
}

// ParseRCT reports the trailer of a frame, if it has a valid one: the suffix is 0x88FB
// and the LSDU size matches the frame. A frame that fails either test is treated as
// coming from a node that is not doubly attached.
func ParseRCT(frame []byte) (RCT, bool) {
	if len(frame) < ethHeader+RCTSize {
		return RCT{}, false
	}
	t := frame[len(frame)-RCTSize:]
	if binary.BigEndian.Uint16(t[4:]) != EtherTypePRP {
		return RCT{}, false
	}
	v := binary.BigEndian.Uint16(t[2:])
	r := RCT{Seq: binary.BigEndian.Uint16(t), Lan: uint8(v >> 12), LSDU: v & maxLSDU}
	if int(r.LSDU) != lsduSize(frame) || (r.Lan != LANA && r.Lan != LANB) {
		return RCT{}, false
	}
	return r, true
}

// StripRCT removes a valid trailer. Padding added to reach the minimum size stays, as
// the standard leaves it to the upper layers.
func StripRCT(frame []byte) ([]byte, RCT, bool) {
	r, ok := ParseRCT(frame)
	if !ok {
		return frame, RCT{}, false
	}
	return frame[:len(frame)-RCTSize], r, true
}

// HSRTag is the 6-byte HSR tag that follows the source MAC: EtherType 0x892F, then
// path (4 bits) and LSDU size (12 bits), the sequence number, and the EtherType of the
// encapsulated frame.
type HSRTag struct {
	Path  uint8
	LSDU  uint16
	Seq   uint16
	Encap uint16
}

// AddHSRTag inserts the tag into an untagged Ethernet frame and pads it to the
// minimum tagged size (60 + 6). Path is 0 on port A and 1 on port B.
func AddHSRTag(frame []byte, path uint8, seq uint16) ([]byte, error) {
	if len(frame) < ethHeader {
		return nil, ErrShort
	}
	if vlanTagged(frame) {
		return nil, ErrVLAN
	}
	if path > 0xF {
		return nil, ErrFormat
	}
	out := make([]byte, 0, len(frame)+HSRTagSize+minFrame)
	out = append(out, frame[:12]...)
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // EtherType, path/LSDU, sequence, encapsulated EtherType
	binary.BigEndian.PutUint16(out[12:], EtherTypeHSR)
	out = append(out, frame[14:]...)
	for len(out) < minFrame+HSRTagSize {
		out = append(out, 0)
	}
	lsdu := len(out) - ethHeader
	if lsdu > maxLSDU {
		return nil, ErrSize
	}
	binary.BigEndian.PutUint16(out[14:], uint16(path)<<12|uint16(lsdu))
	binary.BigEndian.PutUint16(out[16:], seq)
	copy(out[18:20], frame[12:14])
	return out, nil
}

// ParseHSRTag reads the tag of an HSR frame, checking the LSDU size.
func ParseHSRTag(frame []byte) (HSRTag, bool) {
	if len(frame) < ethHeader+HSRTagSize || binary.BigEndian.Uint16(frame[12:]) != EtherTypeHSR {
		return HSRTag{}, false
	}
	v := binary.BigEndian.Uint16(frame[14:])
	t := HSRTag{Path: uint8(v >> 12), LSDU: v & maxLSDU, Seq: binary.BigEndian.Uint16(frame[16:]), Encap: binary.BigEndian.Uint16(frame[18:])}
	if int(t.LSDU) != len(frame)-ethHeader {
		return HSRTag{}, false
	}
	return t, true
}

// StripHSRTag restores the untagged frame (the padding added for the tag stays).
func StripHSRTag(frame []byte) ([]byte, HSRTag, bool) {
	t, ok := ParseHSRTag(frame)
	if !ok {
		return frame, HSRTag{}, false
	}
	out := make([]byte, 0, len(frame)-HSRTagSize)
	out = append(out, frame[:12]...)
	out = append(out, frame[18:20]...)
	out = append(out, frame[20:]...)
	return out, t, true
}
