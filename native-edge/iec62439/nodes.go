package iec62439

import "time"

// Supervisor produces the periodic supervision frames of a doubly attached node: one
// copy per LAN every LifeCheckInterval, sharing a sequence number, each wrapped in an RCT.
type Supervisor struct {
	MAC    [6]byte
	RedBox *[6]byte // set when this node is a RedBox for the MAC in Node
	// DuplicateAccept announces a node that does not discard duplicates itself (type 21).
	DuplicateAccept bool

	seq  uint16
	rct  uint16
	next time.Time
}

// Due returns the A and B copies when a supervision frame is due, else nil.
func (s *Supervisor) Due(now time.Time) (a, b []byte) {
	if now.Before(s.next) {
		return nil, nil
	}
	s.next = now.Add(time.Duration(LifeCheckInterval))
	typ := uint8(TLVPRPDD)
	if s.DuplicateAccept {
		typ = TLVPRPDA
	}
	f := BuildSupervision(s.MAC, Supervision{Version: 1, Seq: s.seq, Type: typ, Node: s.MAC, RedBox: s.RedBox})
	s.seq++
	// Supervision frames carry their own RCT sequence like any other PRP frame.
	a, _ = AppendRCT(f, s.rct, LANA)
	b, _ = AppendRCT(f, s.rct, LANB)
	s.rct++
	return a, b
}

// NodeInfo is what the node table knows about one peer.
type NodeInfo struct {
	LastA, LastB time.Time // last frame seen on each LAN
	Accept       bool      // peer announced duplicate-accept
	RedBox       *[6]byte
}

// Nodes is the table built from received supervision frames.
type Nodes struct {
	m map[[6]byte]*NodeInfo
}

func NewNodes() *Nodes { return &Nodes{m: map[[6]byte]*NodeInfo{}} }

// Observe records a received frame (supervision or data) from src on a LAN.
func (n *Nodes) Observe(src [6]byte, lan uint8, now time.Time) {
	i := n.m[src]
	if i == nil {
		i = &NodeInfo{}
		n.m[src] = i
	}
	if lan == LANA {
		i.LastA = now
	} else if lan == LANB {
		i.LastB = now
	}
}

// Supervision records a parsed supervision frame received on a LAN.
func (n *Nodes) Supervision(s Supervision, lan uint8, now time.Time) {
	n.Observe(s.Node, lan, now)
	i := n.m[s.Node]
	i.Accept = s.Type == TLVPRPDA
	i.RedBox = s.RedBox
}

// Get returns a copy of a node's info.
func (n *Nodes) Get(src [6]byte) (NodeInfo, bool) {
	i := n.m[src]
	if i == nil {
		return NodeInfo{}, false
	}
	return *i, true
}

// LANDown reports which LANs have been silent for more than 2.5 life-check intervals
// (the standard's tolerance of one lost supervision frame plus jitter) for a known node.
func (n *Nodes) LANDown(src [6]byte, now time.Time) (a, b bool) {
	i := n.m[src]
	if i == nil {
		return false, false
	}
	limit := time.Duration(LifeCheckInterval) * 5 / 2
	return now.Sub(i.LastA) > limit, now.Sub(i.LastB) > limit
}

// Forget removes nodes silent on both LANs for NodeForgetTime.
func (n *Nodes) Forget(now time.Time) int {
	gone := 0
	for k, i := range n.m {
		last := i.LastA
		if i.LastB.After(last) {
			last = i.LastB
		}
		if now.Sub(last) > time.Duration(NodeForgetTime) {
			delete(n.m, k)
			gone++
		}
	}
	return gone
}
