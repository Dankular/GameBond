package bond

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// This file is the client half of Receiver. A client Receiver is built from a
// "client" Codec, is given its uplinks up front with AddClientPath (one local
// socket per uplink, all talking to one server endpoint), and learns nothing
// from the network: a datagram from an unconfigured (socket, endpoint) is
// dropped before any state changes, exactly as in the Python client.

var errNotClient = errors.New("operation requires a client receiver")

// freshPath builds a path with a new random transmit epoch and an initial
// budget, without registering it.
func (r *Receiver) freshPath(local int, endpoint netip.AddrPort, now time.Time) (*receivePath, error) {
	var epoch [8]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, err
	}
	p := &receivePath{local: local, endpoint: endpoint, txEpoch: binary.BigEndian.Uint64(epoch[:]), last: now}
	p.budget, _ = NewBudget(r.initialRate, r.maxRate)
	return p, nil
}

// AddClientPath registers an uplink: local is the caller's socket index and
// remote the server's address. Call it before traffic starts; the path stays
// not ready until its handshake completes.
func (r *Receiver) AddClientPath(local int, remote netip.AddrPort, now time.Time) error {
	if r.role != "client" {
		return errNotClient
	}
	if local < 0 || !remote.IsValid() || !remote.Addr().Is4() {
		return ErrFrame
	}
	if r.paths[PathKey{local, remote}] != nil {
		return ErrFrame
	}
	_, err := r.newPath(local, remote, now)
	return err
}

// clientPoll sends the next HELLO or RESET for a path that is not ready or has
// gone silent. A restarted attempt marks the path not ready.
func (r *Receiver) clientPoll(p *receivePath, now time.Time, out *ReceiveResult) error {
	kind, payload, restarted, err := p.hello.Poll(p.ready, now)
	if err != nil {
		return err
	}
	if restarted {
		p.ready = false
	}
	return r.write(kind, payload, p.local, p.endpoint, out)
}

// clientHandshake consumes an authenticated CHALLENGE or READY on a configured
// path. Only a READY proving both nonces under the challenging prefix adopts
// the peer and makes the path ready.
func (r *Receiver) clientHandshake(p *receivePath, packet Packet, now time.Time) (ReceiveResult, error) {
	var out ReceiveResult
	reply, ready, peer, ok := p.hello.Handle(packet, now)
	if !ok {
		r.stats.HandshakeRejected++
		return out, nil
	}
	if reply != nil {
		return out, r.write(reply.Kind, reply.Payload, p.local, p.endpoint, &out)
	}
	if ready {
		if err := r.adoptClientPeer(peer, packet.Header.Sequence, now); err != nil {
			return out, err
		}
		p.ready = true
		p.last = now
	}
	return out, nil
}

// adoptClientPeer mirrors Node._adopt_peer for a client. A new peer prefix
// resets replay, reorder and the probe table, and returns every configured
// path to a fresh state while keeping each path's in-flight handshake so
// parallel attempts on the other uplinks are not thrown away.
func (r *Receiver) adoptClientPeer(peer [16]byte, sequence uint64, now time.Time) error {
	if r.handshake.hasPeer && r.handshake.peer == peer {
		return nil
	}
	if r.handshake.hasPeer {
		r.stats.PeerRestarts++
	}
	r.handshake.peer, r.handshake.hasPeer = peer, true
	clear(r.probes)
	r.replay = ReplayWindow{}
	r.floor = sequence + 1
	r.reorder, _ = NewReorder(DefaultReorderConfig())
	r.reorder.config.Timeout = r.reorderBase
	for _, p := range r.paths {
		fresh, err := r.freshPath(p.local, p.endpoint, now)
		if err != nil {
			return err
		}
		fresh.hello = p.hello
		*p = *fresh // in place: callers and the sender keep valid path pointers
	}
	return nil
}
