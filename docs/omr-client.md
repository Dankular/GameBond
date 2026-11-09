# GameBond client for OpenMPTCProuter servers (Glorytun UDP)

`gamebond/omr_glorytun.py` is a client for the **Glorytun UDP** tunnel that an
OpenMPTCProuter (OMR) server runs on UDP 65001. It needs no MPTCP, and no
virtual adapter: it carries the raw IP packets GameBond's userspace stack
already produces. Several local addresses (one per uplink) join one session and
packets are striped per packet by configured rate.

It was written from the exact sources OMR's server installs (`ysurac/glorytun`
2310047 with `angt/mud` e991dc9): framing, ChaCha20-Poly1305 with the 6-byte
time as nonce and AAD, keyed-BLAKE2b session keys over an X25519 exchange, the
125-byte control message, the three-step handshake, MTU search and the path
state machine.

Install the dependency with `pip install 'gamebond[omr]'` (PyNaCl). OMR uses
libsodium's original 8-byte-nonce ChaCha20-Poly1305, which the `cryptography`
package does not offer.

## What is NOT there yet

- It is wired into the runtime only as the OMR leg of `server_type: "both"`
  ([side-by-side.md](side-by-side.md)); there is no GUI for it yet.
- No admin-API client yet (`/token`, `/config`, `/wan`).
- IPv4 only, ChaCha only, client side only.
- On this path GameBond cannot replicate packets or reorder: the protocol has
  no sequence numbers, so its replicated gameplay queue, reorder buffer and
  adaptive QoS do not apply. Downloads arrive in the order the server's
  striping delivers them.
- The client clock must be within about 10 minutes of the server's.
- The server keeps one peer per tunnel: do not run a real OMR router and this
  client with the same key at the same time.

## Verification status

Verified by `tests/test_omr_glorytun.py` (13 tests): packet layout and tamper
detection, the control message layout, complementary session keys, the full
handshake, MTU search converging below a limited path, data both ways, two
local addresses forming one session with traffic on both, rejection of a wrong
key and of clock skew, client key rotation, and junk datagrams.

**Not verified: interoperability with the real glorytun binary.** The tests run
against `tests/mud_peer.py`, a server written from the same reading of the
source, so a shared misreading would pass them. The check that matters needs
the real software. Two ways, either of which you can run:

1. Against your own OMR VPS (the real test, and the quickest):
   ```sh
   pip install 'gamebond[omr]'
   python tools/probe_omr_glorytun.py --server VPS_IP:65001 --key-file glorytun.key \
       --local YOUR_UPLINK_IP --local YOUR_SECOND_UPLINK_IP --ping
   ```
   The key is `GLORYTUN_PASS` from `/root/openmptcprouter_config.txt` on the VPS
   (64 hex characters). `--ping` sends ICMP echo from the router tunnel address
   `10.255.254.2` to the server's `10.255.254.1` (OMR's defaults, from its
   installer) and reports whether the server answered. Exit code 0 means the
   handshake completed and, with `--ping`, packets passed both ways.
2. Against the pinned real binary built locally. The assistant session that
   wrote this was not permitted to compile and run third-party code, so this was
   not done. The source is `https://github.com/ysurac/glorytun` at
   `23100474922259d00a8c0c4b00a0c8de89202cf9`, with its submodules at the commits
   in its `.gitmodules` state (`angt/mud` e991dc9, which pulls `angt/aegis256`
   577ae03, and `angt/argz` eb8b122); it builds with meson and libsodium.

One behavior carried over from the source and not understood: the original
only recomputes its pending session keys when the *peer's* public key changes,
so a client-side key rotation does not change the keys in use (the server keeps
decrypting with its current ones). Traffic continues, which the rotation test
checks, but whether the server ever adopts the rotated keys was not determined.
