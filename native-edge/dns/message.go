// Package dns is the Go port of gamebond/dns.py: a bounded, exact-host DNS
// override responder. Configured names never fall through to upstream, not even
// for absent AAAA records. No OS resolver or hosts file is touched.
package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

const (
	MaxQuery    = 4096
	MaxResponse = 65535
)

var ErrFormat = errors.New("dns: format error")

func fe(msg string) error { return errors.Join(ErrFormat, errors.New(msg)) }

// NormalizeName lower-cases an exact hostname. Python also IDNA-encodes
// non-ASCII labels; this port rejects them instead (see the ledger).
func NormalizeName(name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	total := 1
	for i, l := range labels {
		l = strings.ToLower(l)
		if l == "" || len(l) > 63 {
			return "", errors.New("an exact DNS hostname is required; wildcards are unsupported")
		}
		for _, c := range []byte(l) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", errors.New("an exact DNS hostname is required; wildcards are unsupported")
			}
		}
		labels[i] = l
		total += len(l) + 1
	}
	if total > 255 {
		return "", errors.New("an exact DNS hostname is required; wildcards are unsupported")
	}
	return strings.Join(labels, "."), nil
}

// Question is the single parsed question of a query.
type Question struct {
	Labels  [][]byte
	Kind    uint16
	Class   uint16
	UDPSize int
}

func (q Question) Name() string {
	parts := make([]string, len(q.Labels))
	for i, l := range q.Labels {
		parts[i] = strings.ToLower(string(l))
	}
	return strings.Join(parts, ".")
}

func (q Question) wire() []byte {
	var b []byte
	for _, l := range q.Labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, byte(q.Kind>>8), byte(q.Kind), byte(q.Class>>8), byte(q.Class))
}

func readName(p []byte, off int) (labels [][]byte, end int, err error) {
	visited := map[int]bool{}
	consumed := -1
	wire := 1
	for i := 0; i < 128; i++ {
		if off >= len(p) || visited[off] {
			return nil, 0, fe("DNS compression loop or truncated name")
		}
		visited[off] = true
		size := int(p[off])
		if size&0xC0 == 0xC0 {
			if off+1 >= len(p) {
				return nil, 0, fe("truncated DNS compression pointer")
			}
			if consumed < 0 {
				consumed = off + 2
			}
			off = (size&63)<<8 | int(p[off+1])
			continue
		}
		if size&0xC0 != 0 || size > 63 {
			return nil, 0, fe("invalid DNS label")
		}
		off++
		if size == 0 {
			if consumed >= 0 {
				return labels, consumed, nil
			}
			return labels, off, nil
		}
		if off+size > len(p) {
			return nil, 0, fe("truncated DNS label")
		}
		label := p[off : off+size]
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return nil, 0, fe("unsupported DNS hostname label")
			}
		}
		labels = append(labels, label)
		wire += size + 1
		if wire > 255 {
			return nil, 0, fe("DNS name exceeds 255 bytes")
		}
		off += size
	}
	return nil, 0, fe("DNS name traversal limit")
}

// ParseQuestion mirrors parse_question; response selects response parsing.
func ParseQuestion(p []byte, response bool) (Question, error) {
	limit := MaxQuery
	if response {
		limit = MaxResponse
	}
	if len(p) < 12 || len(p) > limit {
		return Question{}, fe("invalid DNS message length")
	}
	flags := binary.BigEndian.Uint16(p[2:])
	qd, an, ns, ar := binary.BigEndian.Uint16(p[4:]), binary.BigEndian.Uint16(p[6:]), binary.BigEndian.Uint16(p[8:]), binary.BigEndian.Uint16(p[10:])
	if qd != 1 || (flags&0x8000 != 0) != response || flags&0x7800 != 0 {
		return Question{}, fe("only one standard DNS question is supported")
	}
	labels, end, err := readName(p, 12)
	if err != nil {
		return Question{}, err
	}
	if end+4 > len(p) {
		return Question{}, fe("truncated DNS question")
	}
	q := Question{Labels: labels, Kind: binary.BigEndian.Uint16(p[end:]), Class: binary.BigEndian.Uint16(p[end+2:]), UDPSize: 512}
	end += 4
	if !response {
		if an != 0 || ns != 0 || ar > 1 {
			return Question{}, fe("unexpected records in DNS query")
		}
		if ar != 0 {
			optName, optEnd, err := readName(p, end)
			if err != nil {
				return Question{}, err
			}
			if optEnd+10 > len(p) {
				return Question{}, fe("truncated EDNS record")
			}
			optType := binary.BigEndian.Uint16(p[optEnd:])
			size := int(binary.BigEndian.Uint16(p[optEnd+2:]))
			ttl := binary.BigEndian.Uint32(p[optEnd+4:])
			length := int(binary.BigEndian.Uint16(p[optEnd+8:]))
			if len(optName) != 0 || optType != 41 || (ttl>>16)&255 != 0 || optEnd+10+length != len(p) {
				return Question{}, fe("unsupported or invalid EDNS record")
			}
			q.UDPSize = max(512, min(MaxQuery, size))
			end = optEnd + 10 + length
		}
		if end != len(p) {
			return Question{}, fe("unexpected trailing DNS query bytes")
		}
	}
	return q, nil
}

type answer struct {
	kind uint16
	addr netip.Addr
}

func header(tx, flags uint16, qd, an int) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h, tx)
	binary.BigEndian.PutUint16(h[2:], flags)
	binary.BigEndian.PutUint16(h[4:], uint16(qd))
	binary.BigEndian.PutUint16(h[6:], uint16(an))
	return h
}

func response(query []byte, q *Question, rcode int, authoritative bool, answers []answer, ttl int, tcp bool) []byte {
	var tx, reqFlags uint16
	if len(query) >= 2 {
		tx = binary.BigEndian.Uint16(query)
	}
	if len(query) >= 4 {
		reqFlags = binary.BigEndian.Uint16(query[2:])
	}
	flags := 0x8000 | reqFlags&0x0100 | uint16(rcode)
	if authoritative {
		flags |= 0x0400
	}
	var body []byte
	qd := 0
	if q != nil {
		body = q.wire()
		qd = 1
	}
	var recs []byte
	for _, a := range answers {
		raw := a.addr.AsSlice()
		recs = append(recs, 0xc0, 0x0c, byte(a.kind>>8), byte(a.kind), 0, 1)
		recs = binary.BigEndian.AppendUint32(recs, uint32(ttl))
		recs = binary.BigEndian.AppendUint16(recs, uint16(len(raw)))
		recs = append(recs, raw...)
	}
	out := append(append(header(tx, flags, qd, len(answers)), body...), recs...)
	if !tcp && q != nil && len(out) > q.UDPSize {
		out = append(header(tx, flags|0x0200, 1, 0), body...)
	}
	return out
}
