# Python -> Go parity ledger

Goal: feature parity with the Python codebase, then retire Python entirely.
This file is the checklist. A module is **parity** only when its Python tests'
behaviour is reproduced in Go by tests that would fail if it were not (shared
vectors, or interop against the live Python peer). "Has Go counterpart" means a
Go file exists but parity has **not** been established. Update this file in the
same commit as any change to a row.

Baseline when this ledger was written: 15,126 lines of Python (`gamebond/`),
511 Python test functions in 68 files; Go has about 3,500 lines and 51 test
functions in `native-edge/`, plus the Windows proxy in `netstack/`.

Status keys: **DONE** parity shown | **PART** partly ported | **GO?** Go
counterpart exists, parity unverified | **TODO** nothing in Go | **DECIDE** needs
a product decision before work starts.

## 1. Data plane (the double-coding problem)

| Python | Lines | Go | Status | Evidence / gap |
|---|---:|---|---|---|
| `bonding.py` PathBudget | 467 | `bond/budget.go` | DONE | 94,607 ops replayed from `budget-vectors.json.gz` |
| `path_quality.py` CopyLedger, MtuProber | 180 | `bond/path_quality.go` | DONE (logic) | 55k ops replayed from `path-quality-vectors.json.gz`. MTUProber is wired; CopyLedger is not |
| `transport.py` handshake, client | ~300 | `bond/client_handshake.go`, `bond/client_receiver.go` | DONE | interop with the real Python server: `tools/check_native_client.py`, 1-3 uplinks |
| `transport.py` bonded send/receive, probes, feedback | ~600 | `bond/sender.go`, `receiver.go` | PART | Go client <-> Python server verified; Python client <-> Go server verified (`check_native_receiver.py`) |
| `transport.py` LINK_POLICY sender (client) | ~80 | `bond/client_receiver.go` (`SetClientLinkPolicies`) | DONE (data plane) | policy sent on READY and every 1 s, re-sent until acked; unconfirmed/never/blocked paths carry no payload; unit test + `check_native_client.py --policy` against the Python server. Usage ledger / billing cycle (`link_limits.py`) still unported |
| `transport.py` wire kinds DATA_COPY, MTU_PROBE, MTU_ACK, REPAIR_NA, COPY_REPORT | ~250 | `bond/codec.go`, `receiver.go`, `sender.go`, `repair.go` | PART | kinds 13-17 accepted; MTU discovery (probe/ack, per-path fit in urgent/bulk/repair) verified live both ways: `check_native_client.py --mtu`, unit `TestMTUDiscoveryFindsPerUplinkLimitAndSenderFitsPaths`. **Open:** `loss_tracking` (DATA_COPY is only accepted as data, CopyLedger not wired, COPY_REPORT only stored), sending REPAIR_NA, DF socket option / `df_enforced`, `path_mtu_discovery` key in `edge/config.go` |
| `transport.py` `failover_replay` | ~140 | `bond/failover.go`, `bond/failover_test.go` | PART | Suspect path, bulk avoidance, replay of up to 512 cached packets (16 per tick) and counters ported, opt-in via `Sender.EnableFailover`. Unit-tested in memory with a blackholed uplink (mutation-checked). Go client interoperates with the Python server on loopback (2 and 3 uplinks, `check_native_client.py --failover`). Blackhole of one uplink mid-stream against the Python server (`--blackhole 2 --blackhole-ms 300`, 20 Mbit/s): without failover 924/1500 and 1424/2000 delivered; with it 1436/1500 and 1936/2000. The remaining 64 are exactly the packets beyond the 512-per-suspicion replay cap (512 replayed in both), the same bound as Python; the blackhole check does not yet assert full recovery. No Python-vs-Go replay vectors; no real-adapter run |
| `transport.py` NAT-rebind / epoch path move | ~60 | `receiver.go` | GO? | server side present |
| `link_policy.py` LinkPolicy, UsageLedger, caps | ~150 | `linkpolicy/` | PART | Validation, `effective()` (stop/throttle), `cycle_start`, ledger accounting and the version-1 ledger file match Python on generated vectors (`tools/generate_native_linkpolicy_vectors.py`: 300 cycles, 300 policies, 500 ledger ops, 504 usage checks; mutation-checked) and Go reads Python's file. `Meter` + `cmd/client` meter wire bytes, persist the ledger, and push cap-driven policy updates through `Client.SetPolicies`; `check_go_daemon.py` shows a 30 kB daily cap blocking one uplink as seen by the Python server. `eligible_roles` is covered by `Sender.eligible`, not vectored. Not done: widget/glass settings editing of policies, sharing the ledger concurrently with a running Python process, over-limit throttle exercised end to end |
| `userspace.py` netstack stdio framing (`!BH` kind/size, kinds 0/2/3) | ~30 | `stackio/` | PART | Frame codec only, byte-compatible with Python's `struct.pack('!BH')`, unit-tested. `stackio.Bridge` joins the netstack stdio to `client.Client` (unit-tested with fakes). `cmd/client` reads `local-client.json` (`bind`, `peer`, `session`, `interface_indices`, `game_udp_ports`), marks/classifies outbound packets, and passed `tools/check_go_daemon.py` on loopback: Python server received 200/200 packets over 2 uplinks with game UDP marked DSCP 46, and 50+ Python->Go replies were injected into the (scripted fake) stack. `tools/check_go_daemon_netstack.py` runs the real `gamebond-netstack.exe`: a SOCKS5 CONNECT makes it emit a real TCP SYN that crosses the Go daemon and two bonded uplinks to the Python server, and a SYN-ACK from the server travels back and completes the SOCKS connect (loopback only, no data transfer). Not run against a real adapter or the VPS; writes an atomic Python-shaped subset of `userspace-status.json` (`status/` package; checked by `check_go_daemon.py`: pid, state, per-path ready, packet counters) and answers every `app_authorization_request` with deny/bulk (Python's no-capture-extension answer). Still missing: usage caps, runtime link-policy updates, LAN gateways, OMR, DNS status, capture extension, most status fields (`link_usage`, `qos`, `application*`) |
| `transport.py` UDP socket layer (Windows adapter pinning, `interface_indices`, send/recv buffers) | ~300 | `edge/runtime_linux.go` (Linux server), `uplink/` | PART | `uplink.Open` binds a local IPv4 and pins egress (Windows `IP_UNICAST_IF` verified to apply; Linux `SO_BINDTODEVICE` cross-compiles only), sets buffers. Not yet verified to steer traffic between two physical adapters; `interface_indices` discovery and a `cmd/client` daemon (config, stdio frame protocol) still TODO. The run loop itself exists as package `client` (`client.New/Run/Send`, one goroutine owning protocol state; loopback test: 2000/2000 delivered striped over 2 uplinks with policy, MTU discovery and failover on) |
| `reorder.py` | 273 | `bond/reorder.go` | GO? | exercised by interop, no shared vectors |
| `adaptive_qos.py`, `policy.py` | 644 | `bond/qos.go`, `bond/packet.go` (`MarkGameUDP`) | PART | `Classifier` base rules and `mark_game_udp` now match Python on 604 generated vectors (`tools/generate_native_classifier_vectors.py`); the vectors found a missing `fragment_orphan` reason, fixed. Still `AdaptiveQoS` observe/replicate now match Python on 4800 generated steps (`tools/generate_native_qos_vectors.py`, includes `copy_loss`); still missing: scheduler vectors, Go's 4096 flow cache vs Python's 8192, nothing yet feeds `CopySeen/CopyMissed` from the live receiver (copy_loss is always 0 in the daemon), and Python's `classify`/profile override (`app_profile_*`) |
| `link_policy.py`, `link_limits.py` | 172 | `bond/link_policy.go` | GO? | usage ledger / billing cycle not ported |
| `pacing.py` | 25 | in `budget.go` | GO? | |
| `frame_io.py`, `transport_router.py` | 305 | `native-edge/lan` (frame I/O), `native-edge/router` | PART | `frame_io`: memory + Linux AF_PACKET backends (see LAN row). `router`: transport choice, flow stickiness/TTL, fallback, readiness cache, NAT on the OMR leg, inbound merge and counters match Python on 25 scripted scenarios (`tools/generate_native_router_vectors.py`; dyadic clock values to avoid float-vs-integer-ns noise). Not done: the 16384-entry flow-cache eviction is untested, no OMR transport exists in Go (`omr.py`), no link-state/path-update delegation, wired into `cmd/client` for `server_type: both` (see the OMR row); `Ready` for GameBond is any path ready, not Python's per-path enabled/healthy check |
| `outer_transport.py`, `stream_carrier.py` | 428 | `native-edge/carrier` | PART | Wire protocol (PSK challenge/response, 2-byte framing, HTTPS CONNECT to the fixed authority, TLS >=1.2 with CA + hostname checks), `Dial`, `Relay` (auth before any UDP socket, client cap, urgent/bulk queue) and `Socket` (UDP with timed fallback to stream, generation-confirmed health, recovery, bounded queues, counters) are ported. Verified by Go tests and by real interop: Go client to Python `CarrierRelay` and Python `open_client` to Go `Relay` in tcp, tls and https (needs the repo's truststore workaround for Python TLS servers on this workstation). Mutation-checked (bad server proof, urgent boundary). Not done: no vectors for `OuterSettings` from the Python config shape beyond unit tests, no WAN run. Now wired: `client.Config.Outer` wraps each usable uplink in a `carrier.Socket` (`uplink.Control` pins the TCP fallback to the adapter), `cmd/client` reads `outer_transport` (defaults, unknown keys rejected, same validation). The UDP recovery handshake is new in `bond` (`Receiver.StartRecovery`, `ReceiveVia`, `ReturnToUDP`/`Authenticated` results, `ClientHandshake.Restart`) and is verified only by a Go loopback test (`client/carrier_test.go`: UDP dropped by a gate -> stream fallback -> delivery -> UDP restored -> recovery; mutation-checked), NOT by Python vectors or against the Python server; the existing bond vectors still pass. Recovery HELLOs are sent for every stream-mode uplink regardless of link-policy disable, and per-path `available` is only honoured by skipping unspecified bind addresses. Not run on Windows with `IP_UNICAST_IF` or a real WAN |
| `telemetry.py` | 54 | `Session.Stats` | GO? | |

## 2. Client runtime (Windows)

| Python | Lines | Go | Status | Gap |
|---|---:|---|---|---|
| `userspace.py` (ProxiFyre -> netstack -> Node) | 694 | `netstack/` (proxy/capture) | PART | Go owns the IP stack; the transport and orchestration are Python |
| `app.py`, `app_events.py`, `app_policy.py` | 773 | `netstack/app_*.go` | PART | |
| `capture.py`, `tun.py` | 249 | `netstack/capture.go` | PART | |
| `windows_network.py`, `windows_adapters.py` | 727 | `uplink.InterfaceFor` | PART | Only bind-address -> adapter index/name resolution (stdlib `net.Interfaces`, no PowerShell), used by `cmd/client` to pin an uplink when `interface_indices` is absent; unit-tested on loopback. Not ported: route/gateway discovery, link inventory and metered/Wi-Fi/cellular detection, adapter change notifications, hotspot handling, `unavailable_links` |
| `windows_launcher.py`, `windows_packet_filter.py`, `windows_dns.py`, `process_job.py` | 985 | none | TODO | |
| `hardware_monitor.py`, `gpu_monitor.py`, `tray.py` | 336 | none | TODO / DECIDE | |

## 3. Services

| Python | Lines | Go | Status |
|---|---:|---|---|
| `dns.py`, `dns_management.py` | 541 | `native-edge/dns` | PART | config validation, query parsing, override/refuse answers, UDP+TCP responder with upstream forward; byte-identical to Python on 3116 seeded/mutated queries (`tools/generate_native_dns_vectors.py`). Not done: IDNA (non-ASCII names rejected), upstream forwarding unverified against a real resolver, `dns_management` CLI, daemon wiring, `windows_dns` |
| `nat.py` | 281 | `native-edge/nat` | PART | Outbound/inbound/ICMP-error translation, timeouts, eviction and counters byte-identical to Python on 7,640 generated steps with scripted port allocation (`tools/generate_native_nat_vectors.py`); no consumer yet (LAN gateway/OMR path not ported), no race/soak test |
| `lan_gateway.py`, `network_scanner.py` | 879 | `native-edge/lan` + `native-edge/scanner` | PART | LAN gateway/config/frame I/O as before. Scanner: `Normalize`, `ValidateScan` and the version-1 device-history file match Python (301 inventories, 270 scan cases, 20 histories; `tools/generate_native_scanner_vectors.py`); `DiscoveryJob` (bounded workers, cancel, probe panic -> error) tested with fake probes; Windows `TakeInventory` ran passively on this host (2 adapters) and `ICMPProbe` (IcmpSendEcho2Ex) compiles but has **not been run** (it would send ICMP). Not done: Windows packet-filter frame I/O, `load_lan_tunnel_ips`, daemon wiring, float-valued names in inventory (Python prints `3.0`) |
| `admin/` (HTTPS portal, auth, cert, system) | 440 | none | TODO (documented unsupported on the Go edge) |
| `omr_glorytun.py`, `omr_admin.py`, `omr_settings.py` | 999 | `native-edge/omr` (settings, admin client, mud client) | PART | `omr_settings.py` is ported: `LoadServerMode` matches Python on 3086 generated configs (`tools/generate_native_omr_settings_vectors.py`: type/bool/float/int look-alikes, extra and missing keys, IPv4 forms including integers, every numeric and length boundary; 1280 accepted; boundary mutations caught). `omr_admin.py` is ported (`NormalizePin`, `SPKIPin`, `LearnPin`, `AdminClient` Login/Get/GetConfig, `TunnelSettings`): `TunnelSettings` and pin normalization match Python on 1527 generated configs + 12 pins (`tools/generate_native_omr_tunnel_vectors.py`, incl. Python's `$`-allows-newline key quirk and a sweep of address classes); `SPKIPin` equals Python's `spki_pin` on the same certificate; the client is tested against a local pinned TLS server (wrong pin sends no credentials, a refused login is one attempt, stale token clears, 2 MiB response bound, bad JSON). Not verified against a real omr-admin (same caveat as Python). `omr_glorytun.py` is ported as `omr/mud.go` (`omr.Client`: libsodium-original ChaCha20-Poly1305 seal/unseal, keyed-BLAKE2b + X25519 key exchange, 125-byte control message, RTT/jitter estimator, MTU binary search, rate/loss tracking, path status machine, per-packet striping and urgent best-path choice, demotion/recovery assessment, `SetRoles`, `SetRates`, `Stats`). Verified by `tools/generate_native_mud_vectors.py`: a scripted server drives the real Python `MudClient` on a fake clock (patched entropy) and Go must reproduce every outgoing datagram (SHA-256 + length), every decrypted delivery and the full per-path state after each of 62771 steps across 16 scenarios (1-3 paths, roles, prefs, loss, delayed/duplicated/garbage/old/tampered/foreign packets, a 61-minute jump forcing key rotation, heavy traffic reaching loss 254), plus 300 seal vectors against PyNaCl, key-hash, message pack/unpack, RTT and MTU-search vectors. A live loopback test covers the real sockets, reader and timer goroutines (MTU discovery, Ready, data both ways). Mutation-checked; surviving exact-equality boundaries: loss exactly at 5/6, tx accumulator exactly 1001, tx==rx loss accounting, `demote_after` equality, MTU `>=` limit, latency-spike threshold equality, 250 vs 251 ms standby probe, and `rx.loss > loss_limit` is unreachable at the default limit 255. Like the Python it is written from the glorytun sources and has NEVER been run against a real OMR/glorytun server, so interoperability is unproven. Not done: `update_paths` (adapter rebind), the Python-only values above 2^62 in counters, Windows interface pinning is only the `Open` hook (default is `uplink.Open`), `cmd/client` now reads `server_type`/`omr` (`omr.LoadServerMode`) and, for `both`, brings the OMR leg up in the background (`cmd/client/omrleg.go`: key file or pinned admin API, `nat` + `router` + `omr.Client`, retry every 30 s, no retry after a refused login, `omr_leg_up`/`omr_leg_unavailable` lines, `omr` status section); covered by fakes only (routing keeps queue metadata, NAT applied, pass-through before the leg is up, retry/blocked state), never run with a real OMR server or the real VPS config. Python error text is not matched (accept/reject only) |
| `tty_server.py` | 439 | none | TODO |
| `atomic_io.py` | 51 | `native-edge/atomicio` | PART | `ReadBytesShared`/`ReadJSONShared` (4 MiB bound, BOM-tolerant, FILE_SHARE_DELETE open with sharing-violation retry), `ReplaceFile` (`ReplaceFileW` with Python's 1.5 s backoff on Windows, rename elsewhere) and `WriteFileAtomic`. Tested on Windows with 4 readers polling during 300 replacements (no partial reads, no leftover temp files); Linux build vetted only. Not yet used by `status`, `linkpolicy` or `scanner`, which still do their own temp+rename |

## 4. GUI (DECIDE)

`glass_*.py`, `widget.py`, `widget_data.py` are about 4,100 lines of PySide/Qt.
Go has no equivalent toolkit in the repo. Retiring Python means choosing one of:
a local web UI served by the Go client (same model as the admin portal),
a Wails/WebView2 shell, or Fyne. This is a product decision and the largest
single item after the data plane. It is **not decided**.

## 5. Tests

511 Python test functions encode behaviour that has to be re-asserted in Go or
retired deliberately. Order of work: wire kinds + `loss_tracking` /
`path_mtu_discovery` -> LINK_POLICY sender -> `failover_replay` -> client I/O
plane (`cmd/client`) -> cutover benchmark -> services -> GUI.

## Cutover criteria (Python may be deleted only when all hold)

1. Every row above is DONE or has an explicit written decision to drop it.
2. Go client <-> Go server passes the interop suite, plus Go<->Python in both
   directions while a mixed deployment exists. **Status:** Go<->Go loopback exists
   (`tools/check_go_to_go.py`; 1-3 uplinks, MTU, policy), Go client -> Python server
   exists, Python client -> Go server exists (`check_native_receiver.py`); Go server ->
   Go client with failover/blackhole cases is still missing.
3. `tools/benchmark_tunnel.py` shows Go at or above Python on the same link.
4. A physical multi-uplink soak (not loopback) has been run. **Nothing in this
   repository has been validated that way yet**, for Python or for Go.

## Loopback throughput findings (one machine; not a link benchmark)

Same 1000-byte payload stream, `tools/check_native_client.py` / `check_go_to_go.py`:

| Pairing | Result |
|---|---|
| Python client -> Python server, 2 uplinks | about 52 Mbit/s |
| Go client -> Python server, 2 uplinks | about 125 Mbit/s plateau (Python receiver is the likely limit) |
| Go client -> Go server, 1 / 2 / 3 uplinks | about 365 / 465 / 452 Mbit/s |
| MTU discovery on vs off | no measurable difference (Python peer: 125.7 vs 125.6; Go peer: 458 vs 466) |
| Go -> Go with a per-uplink policy, 2 uplinks | RESOLVED. It was about 60 Mbit/s for any policy of 50 or more because of two compounding timing limits, not bond logic (virtual clock: 89.8). (1) Go's `time.Now()` on this Windows machine advances only about once per millisecond (measured: 550 distinct readings in 500 ms), so a pacer reading it sees time standing still and releases only its 2,800-byte burst per tick; fixed by `hrclock.Now()` (QueryPerformanceCounter). (2) Sleeping on a ticker between paced releases overshoots by the OS timer granularity; fixed by polling when the next release is under 1 ms away (`client.spinWindow`). Either alone left it at 60-64. Result: `client` test 2x100 Mbit/s policy -> 178.7 Mbit/s payload (about 200 Mbit/s of wire); with the spin disabled it drops to 35.5 and the test fails. `client-probe --spin` with `hrclock` gave 357.7 against a 200 Mbit/s policy. Raw paced UDP on loopback holds its target to 411 Mbit/s, so the OS was not the limit. Not yet: the real Windows daemon on a physical adapter |

Harness lesson: a 2 ms loop tick capped Go at about 300 Mbit/s and made the policy case drop
packets. The real client needs timer-driven pumping, not a coarse poll.

## Per-leg probing (find hidden slowdowns)

`python tools/probe_legs.py --label X [--baseline Y]` measures each leg separately and flags any
metric more than 15% worse than a saved baseline (`evidence/legs-<label>.json`):

1. raw UDP socket (`cmd/leg-probe loopback`), 2. codec CPU (Go benchmarks),
3. protocol logic on a virtual clock with an ideal wire (`bond/virtual_throughput_test.go`),
4. Go client -> Go server, 5. Go client -> Python server, 6. `--remote HOST:PORT` raw UDP to a far
host running `leg-probe serve` (RTT, jitter, loss, throughput), 7. `--tunnel` the live tunnel.

Reading it: each ratio compares a leg with the one beneath it. First run on this machine:
bonded Go gets 0.65 of the raw socket, paced real runs reach 0.67 of the virtual logic, and the
Python server gets 0.25 of the Go server's rate. Legs 6 and 7 have not been run: they need the VPS.
Before deploying, run leg 6 against the VPS (start `leg-probe serve` there) to separate the network
from the software.
