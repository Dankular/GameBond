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
| `transport.py` `failover_replay` | ~140 | none | TODO | Python-only; opt-in |
| `transport.py` NAT-rebind / epoch path move | ~60 | `receiver.go` | GO? | server side present |
| `transport.py` UDP socket layer (Windows adapter pinning, `interface_indices`, send/recv buffers) | ~300 | `edge/runtime_linux.go` (Linux server only) | TODO | client needs per-uplink bind + Windows `IP_UNICAST_IF` |
| `reorder.py` | 273 | `bond/reorder.go` | GO? | exercised by interop, no shared vectors |
| `adaptive_qos.py`, `policy.py` | 644 | `bond/qos.go` | GO? | classifier/QoS present; no shared vectors |
| `link_policy.py`, `link_limits.py` | 172 | `bond/link_policy.go` | GO? | usage ledger / billing cycle not ported |
| `pacing.py` | 25 | in `budget.go` | GO? | |
| `frame_io.py`, `transport_router.py` | 305 | none | TODO | stdio frame protocol with `netstack`; router chooses transport |
| `outer_transport.py`, `stream_carrier.py` | 428 | none | TODO | TCP/QUIC-style fallback carrier |
| `telemetry.py` | 54 | `Session.Stats` | GO? | |

## 2. Client runtime (Windows)

| Python | Lines | Go | Status | Gap |
|---|---:|---|---|---|
| `userspace.py` (ProxiFyre -> netstack -> Node) | 694 | `netstack/` (proxy/capture) | PART | Go owns the IP stack; the transport and orchestration are Python |
| `app.py`, `app_events.py`, `app_policy.py` | 773 | `netstack/app_*.go` | PART | |
| `capture.py`, `tun.py` | 249 | `netstack/capture.go` | PART | |
| `windows_network.py`, `windows_adapters.py` | 727 | none | TODO | adapter/route discovery (PowerShell/WMI today) |
| `windows_launcher.py`, `windows_packet_filter.py`, `windows_dns.py`, `process_job.py` | 985 | none | TODO | |
| `hardware_monitor.py`, `gpu_monitor.py`, `tray.py` | 336 | none | TODO / DECIDE | |

## 3. Services

| Python | Lines | Go | Status |
|---|---:|---|---|
| `dns.py`, `dns_management.py` | 541 | none | TODO |
| `nat.py` | 281 | none (relies on container entrypoint) | TODO |
| `lan_gateway.py`, `network_scanner.py` | 879 | none | TODO |
| `admin/` (HTTPS portal, auth, cert, system) | 440 | none | TODO (documented unsupported on the Go edge) |
| `omr_glorytun.py`, `omr_admin.py`, `omr_settings.py` | 999 | none | TODO |
| `tty_server.py` | 439 | none | TODO |
| `atomic_io.py` | 51 | none | TODO (trivial) |

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
| Go -> Go with a 50 Mbit/s per-uplink policy, 2 uplinks | about 60 Mbit/s payload on real sockets, but 89.8 on the virtual-clock harness (the theoretical figure). The bond logic is correct; the loss is in the probe's I/O loop. Eliminated: policy rate (60 for any policy >= 50), OS timer granularity (busy-spin gives 60-62), budget state (no backoffs, WireLimited 0). Still open: what in the real loop caps paced sending near 7,500 packets/s |

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
