# Native GB03 edge work

This module is the in-progress Go port of the existing VPS packet path. It is
not a replacement production edge yet. The running user's tunnel still uses
the Python server. No physical aggregation improvement has been established.

Why port: the isolated VPS's Python transport measured 8.99 Mbps on a capped
loopback test while using 3.32 CPU seconds in 3.00 wall seconds. Direct physical
kernel TCP measured about 40–42 Mbps on each access link. See
`../evidence/vps-python-transport-ceiling.json` and
`../evidence/direct-physical-kernel-tcp.json`.

Implemented and verified:

- Byte-compatible GB03 HKDF/ChaCha20-Poly1305, separate directional nonce
  domains, bounded authenticated key cache, nonce exhaustion guard.
- Fresh challenge proof before adopting a peer; recorded RESET cannot roll a
  newer peer back. Parallel path challenges survive same-domain connection.
- Bounded replay and per-flow reordering, late first-arrival delivery, gap
  deadlines, capacity handling, idle expiry, bounded repair-hole enumeration.
- Receive-side UDP handshake, probes, striped delivery feedback, replica
  deduplication, authenticated path epoch migration, restart isolation.
- Per-path pacing/congestion budget preserving Python's delivery/pressure
  gates, timeout recovery, urgent physical service accounting, bounded debt,
  and ACK-driven startup. Seven Python-generated traces compare 89,711
  operations and periodic complete statistics snapshots against Go.
- Weighted single-flow transmission over multiple ready paths, with failed-write
  fallback and flow sequence advancement only after a successful socket write.
- Authenticated role and directional wire-limit configuration, cumulative wire
  accounting, strict all-wire transmit pacing, and disabled-path injection drops.
- Bounded priority/bulk queues, TCP ACK/control promotion, deadline expiry,
  priority admission over bulk pressure, and queued plaintext reset on peer restart.
- Bounded recent TCP repair caching and requests, fresh repair nonces, per-flow
  deduplication and two-attempt limits. UDP gameplay does not enter TCP repair.

`cmd/receiver-probe` is a loopback-only test harness. Its default mode uses
immediate single-path DATA echoes to isolate reception. Its optional bonded mode
uses the native sender, bounded queues, pacing and repair. It has a 30-second
lifetime, receives test credentials through stdin,
and does not configure capture, adapters, routes, TUN, or a VPS service.

Build and run receive interoperability from the repository root:

```powershell
$env:GOCACHE="$PWD\.runtime\go-build"
$env:GOMODCACHE="$PWD\.runtime\go-native-mod"
$env:GOPROXY='file:///C:/Users/sysadmin/go/pkg/mod/cache/download'
Push-Location native-edge
go test ./...
go vet ./...
go build -buildvcs=false -o ../build/gamebond-native-receiver-probe.exe ./cmd/receiver-probe
Pop-Location
python tools/check_native_receiver.py
python tools/check_native_receiver.py --bonded
python tools/check_native_receiver.py --bonded --repair --policies
```

The proxy above consumes previously downloaded modules from this workstation's
read-only cache while writing only workspace caches. Checksums remain enabled.
To regenerate the compressed behavioral fixtures:
`python tools/generate_native_budget_vectors.py`.

The socket interoperability checks now exercise both directional repair paths
with one deliberately dropped datagram each way. They also verify primary-only
service while a backup is present, and backup service when the primary is
blocked, in both directions. All payloads arrive exactly once. Gap-deadline
expiry can release a late first arrival after later datagrams; that behavior
avoids manufacturing inner TCP loss and is reported explicitly by the test.

Before a full isolated VPS comparison, implement and integrate bidirectional
application profiles/adaptive redundancy, Linux TUN with source and destination
validation, and daemon lifecycle/metrics. The native code must not be exposed
as the production server yet. TCP/TLS fallback and accounting also need their
integration contracts preserved.

Before production rollout, run Python/native interoperability and adversarial
tests, isolated namespace egress tests, asymmetric delay/loss/rebinding tests,
and repeated physical single/parallel/mixed upload and download comparisons.
Completion requires useful combined payload throughput to exceed the faster
single physical link; microbenchmarks or summed adapter counters cannot prove it.
