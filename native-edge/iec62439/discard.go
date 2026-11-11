package iec62439

import "time"

const (
	blockSeqs = 128
	maxBlocks = 64
)

type block struct {
	base    uint16
	bits    [2]uint64
	updated time.Time
}

type node struct {
	blocks []*block
	seen   time.Time
}

// Discard drops the second copy of each frame, keyed by source MAC and sequence number,
// as a PRP/HSR receiver does. Sequence numbers are tracked in 128-wide bitmap blocks,
// at most 64 per node, and a block is forgotten after EntryForgetTime.
type Discard struct {
	nodes  map[[6]byte]*node
	Passed uint64
	Dups   uint64
}

func NewDiscard() *Discard { return &Discard{nodes: map[[6]byte]*node{}} }

// Accept reports whether the frame (src, seq) is new. A repeat inside EntryForgetTime
// is a duplicate.
func (d *Discard) Accept(src [6]byte, seq uint16, now time.Time) bool {
	n := d.nodes[src]
	if n == nil {
		n = &node{}
		d.nodes[src] = n
	}
	n.seen = now
	base := seq &^ (blockSeqs - 1)
	var b *block
	live := n.blocks[:0]
	for _, x := range n.blocks {
		if now.Sub(x.updated) > time.Duration(EntryForgetTime) {
			continue
		}
		live = append(live, x)
		if x.base == base {
			b = x
		}
	}
	n.blocks = live
	if b == nil {
		if len(n.blocks) >= maxBlocks {
			n.blocks = n.blocks[1:]
		}
		b = &block{base: base}
		n.blocks = append(n.blocks, b)
	}
	off := seq - base
	word, bit := off/64, uint64(1)<<(off%64)
	b.updated = now
	if b.bits[word]&bit != 0 {
		d.Dups++
		return false
	}
	b.bits[word] |= bit
	d.Passed++
	return true
}

// Forget removes nodes not heard from within NodeForgetTime and returns how many.
func (d *Discard) Forget(now time.Time) int {
	gone := 0
	for k, n := range d.nodes {
		if now.Sub(n.seen) > time.Duration(NodeForgetTime) {
			delete(d.nodes, k)
			gone++
		}
	}
	return gone
}
