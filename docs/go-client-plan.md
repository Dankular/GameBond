# Go client role: migration plan

Goal: one implementation of the data plane. Today `native-edge` is a server only;
the Windows client is ProxiFyre -> `netstack` (Go, frames over stdio) ->
`gamebond/userspace.py` + `transport.Node` (Python: multi-path UDP, handshake,
bonding) -> VPS. A Go client replaces the Python `Node` on the client side first,
keeping Python orchestration (adapter selection, status, GUI) until later.

## Why this is not a drop-in

`bond.Receiver` is hard-wired to the server role:

- `NewReceiver` rejects any codec whose role is not `server`.
- It embeds `ServerHandshake`; there is no per-path client state.
- `paths` is keyed by **remote endpoint only**. A client has several local
  sockets (one per uplink) all talking to one server endpoint, so those paths
  collide. Path identity must become (local path index, remote endpoint).
- `Datagram` carries no local socket, so the writer cannot pick an uplink.
- The Python client also sends `LINK_POLICY`, probes configured paths even when
  down, and recovers via HELLO after silence. None of that exists in Go.

## Milestones

1. **Client handshake state machine** (DONE, `bond/client_handshake.go`).
   Faithful port of the client branches of `Node.maintenance` / `Node._handshake`,
   tested against the Go `ServerHandshake`. Not yet wired into anything.
2. **Path identity** (DONE). Add a local path index to `Datagram` and key
   `Receiver.paths` by (index, endpoint). Server behaviour must stay
   byte-for-byte identical (index 0, existing tests and `budget-vectors` unchanged).
3. **Client role in the receiver/sender** (DONE for handshake, probing, bonded send/receive; link-policy sender still open). Relax the server-only checks, drive
   `ClientHandshake.Poll` from `Tick`, adopt the peer on READY, probe configured
   paths, and add the link-policy sender.
4. **Cross-implementation interop tests** (Go client -> Python server DONE: `tools/check_native_client.py`, 1-3 uplinks, 200 payloads each way, striped over every uplink; Python client -> Go client path, blackhole and policy cases still open). Go client <-> Python server and
   Python client <-> Go server, over real loopback UDP, including a blackholed
   path (extend `tools/check_native_receiver.py`).
5. **Client I/O plane.** A `cmd/client` that binds one UDP socket per uplink to
   a chosen adapter address and speaks the existing netstack stdio frame
   protocol (`gamebond/frame_io.py`), so `userspace.py` can swap its `Node` for
   the Go process without touching ProxiFyre.
6. **Parity of Python-only data-plane features** before cutover:
   `path_quality` (loss tracking, MTU discovery) and `failover_replay`.
   Add shared test vectors like `budget-vectors.json.gz`.
7. **Cutover and freeze.** Run `tools/benchmark_tunnel.py` for Python vs Go,
   then stop adding data-plane features to Python.

## Not covered by this plan

DNS, NAT, LAN gateway, the admin portal, Windows adapter/route management and
the Qt GUI stay in Python until the data plane has moved. The admin portal is
documented as unsupported on the Go edge; that does not change here.

## Risks

- Milestone 2 touches the server hot path. Guard it with the existing
  `go test ./...` plus the Python<->Go interop tools before and after.
- Nothing here has been validated on a physical multi-uplink link. Equivalence
  is established by tests and vectors, not by field measurement.
