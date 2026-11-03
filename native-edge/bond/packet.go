package bond

import "encoding/binary"

type IPv4Info struct {
	Source, Destination           [4]byte
	Protocol, DSCP                byte
	Fragmented                    bool
	HeaderLength, TransportOffset int
	Flow                          string
	TCPControl                    bool
	SourcePort, DestinationPort   uint16
	HasPorts                      bool
	FragmentKey, PolicyFlow       string
	FragmentOffset                int
}

func IsTCPControl(packet []byte) bool {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false
	}
	offset := int(packet[0]&15) * 4
	if offset < 20 || offset+20 > len(packet) {
		return false
	}
	flags := packet[offset+13]
	if flags&7 == 0 && (flags&16 == 0 || offset+int(packet[offset+12]>>4)*4 != len(packet)) {
		return false
	}
	p, err := ParseIPv4(packet)
	return err == nil && p.TCPControl
}

// ParseIPv4 validates structural bounds without guessing an application from
// timing, size, or generic QUIC ports. Checksums remain the IP stack's job.
func ParseIPv4(packet []byte) (IPv4Info, error) {
	var p IPv4Info
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return p, ErrFrame
	}
	header := int(packet[0]&15) * 4
	if header < 20 || header > len(packet) || int(binary.BigEndian.Uint16(packet[2:])) != len(packet) {
		return p, ErrFrame
	}
	p.Protocol = packet[9]
	p.DSCP = packet[1] >> 2
	p.HeaderLength = header
	p.TransportOffset = header
	copy(p.Source[:], packet[12:16])
	copy(p.Destination[:], packet[16:20])
	fragment := binary.BigEndian.Uint16(packet[6:])
	p.Fragmented = fragment&0x3fff != 0
	if p.Fragmented {
		length := len(packet) - header
		if length == 0 || (fragment&0x2000 != 0 && length%8 != 0) || int(fragment&0x1fff)*8+length > 65515 {
			return p, ErrFrame
		}
		key := make([]byte, 11)
		copy(key, p.Source[:])
		copy(key[4:], p.Destination[:])
		key[8] = p.Protocol
		copy(key[9:], packet[4:6])
		p.FragmentKey = string(key)
		p.FragmentOffset = int(fragment&0x1fff) * 8
		if p.FragmentOffset == 0 && p.Protocol == 17 {
			if header+8 > len(packet) {
				return p, ErrFrame
			}
			length := int(binary.BigEndian.Uint16(packet[header+4:]))
			if length <= len(packet)-header || length > 65535-header {
				return p, ErrFrame
			}
			p.SourcePort = binary.BigEndian.Uint16(packet[header:])
			p.DestinationPort = binary.BigEndian.Uint16(packet[header+2:])
			p.HasPorts = true
			p.PolicyFlow = normalizedFlow(p.Protocol, p.Source, p.Destination, p.SourcePort, p.DestinationPort)
		}
		return p, nil
	}
	if p.Protocol == 6 {
		if header+20 > len(packet) {
			return p, ErrFrame
		}
		tcpHeader := int(packet[header+12]>>4) * 4
		if tcpHeader < 20 || header+tcpHeader > len(packet) {
			return p, ErrFrame
		}
		flags := packet[header+13]
		p.TCPControl = flags&7 != 0 || (flags&16 != 0 && header+tcpHeader == len(packet))
	} else if p.Protocol == 17 {
		if header+8 > len(packet) || int(binary.BigEndian.Uint16(packet[header+4:])) != len(packet)-header {
			return p, ErrFrame
		}
	} else {
		return p, nil
	}
	p.HasPorts = true
	p.SourcePort = binary.BigEndian.Uint16(packet[header:])
	p.DestinationPort = binary.BigEndian.Uint16(packet[header+2:])
	p.Flow = normalizedFlow(p.Protocol, p.Source, p.Destination, p.SourcePort, p.DestinationPort)
	p.PolicyFlow = p.Flow
	return p, nil
}
func normalizedFlow(protocol byte, source, destination [4]byte, sport, dport uint16) string {
	var a, b [6]byte
	copy(a[:4], source[:])
	binary.BigEndian.PutUint16(a[4:], sport)
	copy(b[:4], destination[:])
	binary.BigEndian.PutUint16(b[4:], dport)
	// Normalize endpoints so inbound app markings also classify return traffic.
	if string(a[:]) > string(b[:]) {
		a, b = b, a
	}
	key := make([]byte, 13)
	key[0] = protocol
	copy(key[1:7], a[:])
	copy(key[7:], b[:])
	return string(key)
}
