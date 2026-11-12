package bond

// SetVersion sets the build id (git commit) this side reports to its peer.
func (r *Receiver) SetVersion(v string) {
	if len(v) > 64 {
		v = v[:64]
	}
	r.version = v
}

// Versions returns this side's build id and the peer's, which is empty until the peer has
// answered (a peer built before the VersionReq/VersionInfo frames never does).
func (r *Receiver) Versions() (local, peer string) { return r.version, r.peerVersion }
