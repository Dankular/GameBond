// Package lan is the Go port of gamebond/lan_gateway.py: a layer-2 gateway that
// answers one LAN device's DHCP and ARP and exchanges IPv4 packets with the
// bonded tunnel. Raw frame I/O is supplied through the IO interface.
package lan

import "encoding/binary"

func checksum(data []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

func buildIPv4(src, dst [4]byte, protocol byte, payload []byte, ident uint16) []byte {
	h := make([]byte, 20, 20+len(payload))
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(h[4:], ident)
	h[8], h[9] = 64, protocol
	copy(h[12:], src[:])
	copy(h[16:], dst[:])
	binary.BigEndian.PutUint16(h[10:], checksum(h, 0))
	return append(h, payload...)
}

func buildUDP(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	length := 8 + len(payload)
	seg := make([]byte, 8, length)
	binary.BigEndian.PutUint16(seg, sport)
	binary.BigEndian.PutUint16(seg[2:], dport)
	binary.BigEndian.PutUint16(seg[4:], uint16(length))
	seg = append(seg, payload...)
	pseudo := append(append(append([]byte{}, src[:]...), dst[:]...), 0, 17, byte(length>>8), byte(length))
	c := checksum(append(pseudo, seg...), 0)
	if c == 0 {
		c = 0xFFFF
	}
	binary.BigEndian.PutUint16(seg[6:], c)
	return seg
}

// parseIPv4 returns the header length, protocol, src, dst and total length.
func parseIPv4(p []byte) (header int, protocol byte, src, dst [4]byte, total int, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	header = int(p[0]&15) * 4
	total = int(binary.BigEndian.Uint16(p[2:]))
	if header < 20 || total < header || total > len(p) {
		return
	}
	copy(src[:], p[12:16])
	copy(dst[:], p[16:20])
	return header, p[9], src, dst, total, true
}

func refreshIPChecksum(p []byte, header int) {
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:], checksum(p[:header], 0))
}

// decrementTTL refuses to forward an expiring packet (nil).
func decrementTTL(p []byte) []byte {
	if p[8] <= 1 {
		return nil
	}
	d := append([]byte(nil), p...)
	d[8]--
	refreshIPChecksum(d, int(d[0]&15)*4)
	return d
}

// clampTCPMSS lowers the MSS option of SYN segments so full-size segments fit.
func clampTCPMSS(p []byte, limit int) []byte {
	header, proto, src, dst, total, ok := parseIPv4(p)
	if !ok || proto != 6 {
		return p
	}
	if binary.BigEndian.Uint16(p[6:])&0x1FFF != 0 {
		return p
	}
	if total < header+20 || p[header+13]&0x02 == 0 {
		return p
	}
	offset := int(p[header+12]>>4) * 4
	if offset < 20 || header+offset > total {
		return p
	}
	data := append([]byte(nil), p[:total]...)
	index, end := header+20, header+offset
	changed := false
	for index < end {
		kind := data[index]
		if kind == 0 {
			break
		}
		if kind == 1 {
			index++
			continue
		}
		if index+1 >= end || data[index+1] < 2 || index+int(data[index+1]) > end {
			break
		}
		if kind == 2 && data[index+1] == 4 {
			if int(binary.BigEndian.Uint16(data[index+2:])) > limit {
				binary.BigEndian.PutUint16(data[index+2:], uint16(limit))
				changed = true
			}
			break
		}
		index += int(data[index+1])
	}
	if !changed {
		return p
	}
	segLen := total - header
	data[header+16], data[header+17] = 0, 0
	pseudo := append(append(append([]byte{}, src[:]...), dst[:]...), 0, 6, byte(segLen>>8), byte(segLen))
	binary.BigEndian.PutUint16(data[header+16:], checksum(append(pseudo, data[header:total]...), 0))
	return data
}

// fragmentIPv4 splits a packet whose DF bit is clear, honouring existing fragment fields.
func fragmentIPv4(p []byte, mtu int) [][]byte {
	header := int(p[0]&15) * 4
	payload := p[header:]
	flags := binary.BigEndian.Uint16(p[6:])
	base := int(flags & 0x1FFF)
	more := flags&0x2000 != 0
	step := (mtu - header) / 8 * 8
	if step <= 0 {
		return nil
	}
	var pieces [][]byte
	for start := 0; start < len(payload); start += step {
		chunk := payload[start:min(start+step, len(payload))]
		last := start+step >= len(payload)
		field := uint16((base + start/8) & 0x1FFF)
		if more || !last {
			field |= 0x2000
		}
		d := append(append([]byte{}, p[:header]...), chunk...)
		binary.BigEndian.PutUint16(d[2:], uint16(len(d)))
		binary.BigEndian.PutUint16(d[6:], field)
		refreshIPChecksum(d, header)
		pieces = append(pieces, d)
	}
	return pieces
}
