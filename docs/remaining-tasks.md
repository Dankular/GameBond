# Remaining tasks: Python to Go migration

Goal (still active): feature parity of the Python codebase in Go, then retire Python entirely.
**Status: NOT met. Do not delete any Python code or the Python rollback release until every cutover criterion holds.**

Source of truth is `docs/go-migration-ledger.md`. Update the ledger in the same commit as any row change.
Work is committed locally; do not push without being asked. See the local Git log for the latest implementation commit.

2026-11-09 settings/PS5 update: the Go desktop now has structured DNS and link
limits, Connected devices, OMR key/admin settings, application capture mode,
and offline saved adapter selection. Isolated Edge checks covered the settings
forms; Go endpoint tests cover validation and private OMR password storage.
Connected devices searches USB hardware/parent descriptions for UGREEN every
15 seconds while open, distinguishes chipset-only candidates, excludes uplinks,
and prefills an unchecked PS5 profile for one confirmed match. Actual Windows
inventory has no USB Ethernet adapter yet. Simulated UGREEN detection/prefill
passed with no page errors. No PS5 gateway was activated or VPS config changed.
The daemon now supplies uplink GUIDs to LAN validation and rejects index overlap
before opening the driver. Physical UGREEN/PS5, server allowlisting and live LAN
forwarding checks remain open. Desktop parity remains PART; older notes below
about JSON editors/missing settings and absent saved adapter selection are
superseded by this update. Scanner, journal and other listed gaps remain open.

## Working rules and constraints (from the user)

- Do not ask for approval; do the work. Do not repeat status text. Do not claim completion.
- Python code and the Python rollback release `/opt/gamebond/releases/git-41e6b3393e74-30c2e0` are deleted only when ALL cutover criteria hold.
- Use `git -c safe.directory='*' ...` per command (the global git config change was denied).
- Leave the six pre-existing `gamebond-netstack.exe` processes alone.
- Do not put a main NIC into packet-filter tunnel mode.
- Go files with backslashes or quotes: write with the Write/Edit tools. Bash heredocs and Python string edits halve backslashes (use `chr(92)` in Python edits). Several bugs this session came from that.
- Build with `GOFLAGS=-buildvcs=false` (set it on every `go` command; it does not persist between Bash calls). The edge is linux-only: `GOOS=linux go build -o ../build/gamebond-native-edge-linux ./cmd/edge`.
- Remote commands to the VPS: `scratchpad/r.py "<cmd>"` (plink). Beware `$` in remote heredocs (the shell eats them; pass data via base64).

## 1. GUI (ledger section 4, row PART) - the main coding left

Decision (user): PORT, including the existing desktop widget (the user rejected a browser dashboard as its replacement, and rejected a simplified dark native mock-up). `cmd/tray` now hosts the Go-served desktop UI in a standalone WebView2 window. Tray Show/click opens that window; the browser dashboard is a separate explicit menu command. The desktop uses the existing light theme, fonts and icons, original navigation and traffic layout. `start-widget.cmd` launches `build/gamebond-widget.exe`. GUI parity remains PART for the gaps below.

Added and verified on 2026-11-09:
- **Per-app policy editor:** `/api/app-policy` and a form with protection toggle, default profile, and add/remove executable rules. Uses `apppolicy.New`; saves related keys together, preserves other config and the previous file. Endpoint tests and headless Edge checks cover normalization, save and invalid-path rejection.
- **Adapter selection:** read-only Windows `GetAdaptersAddresses` discovery includes gateways and stable identities. The dashboard saves 1-8 selections to `bind`, `interface_indices`, `interface_ids`, `interface_names`, `gateways`; offline links use `0.0.0.0`. Tested with injected adapters and real read-only Windows discovery (Ethernet 22, 192.168.1.93 via 192.168.1.1). Saving/restarting a physical selection remains unverified; missing saved adapter GUIDs are retained by the selector.
- **Dashboard browser check:** headless Edge rendered the page, exercised policy changes using an isolated config, and reported no script errors. Screenshots inspected at `.runtime/dashboard-preview/policy.png` and `adapters.png`. Fixed literal newlines in JavaScript strings that previously prevented the script parsing.
- **Link policy validation:** the daemon now rejects unknown and mis-cased fields, including null/non-object policies; dashboard validation delegates to it.
- **Single-link behavior (user clarification):** one link runs the VPN; additional active links enable bonding. Go/Python validators and selectors now allow 1-8 links. Regenerated config vectors: 29,544 cases, 5,907 accepted. `tools/check_go_daemon.py --uplinks 1|2 --client <rebuilt daemon>` passes (200 uploads, 100 game-marked, 50 returns each). New client test starts with one usable path and an offline slot, verifies delivery, restores the second path and verifies striping, then removes it and verifies delivery continues. Stable identities now drive daemon adapter polling, including DHCP/index changes and startup parking; inventory/bind failures are retried.
- **Live metrics and state:** fixed `hwmon.ifRow` returning the struct before `GetIfEntry2Ex` filled it (empty adapter names/zero counters). Regression test checks actual names/byte counters. Desktop shows physical adapter rates independently of VPN traffic. The default Live graph uses measured adapter rates/timestamps and fills the active history window immediately; VPN-only counters remain selectable. Browser check matched the plotted value to the actual adapter reading (e.g. 47.63 Mbps down / 5.09 Mbps up), with no page errors. UI lifecycle comes from the supervisor instead of stale status files; mocked stop UI check shows Disconnected/Connect without altering the real daemon. `ReadStatus` tests cover stale/missing files and stopped/restarting states.
- **Single physical link:** `tools/check_single_link_vpn.py` verified exit IP 195.154.119.136 and increasing outbound/injected counters with one healthy Go path; evidence is `evidence/single-link-vpn.json` (git-ignored). The check uses shared Windows file reads with bounded retry. The running native widget has real metrics; the supervisor remains running as the user left it.

Scanner verification (2026-11-09): `go test ./...` passes on Windows. Endpoint tests prove passive reads send no probes, reject public/off-subnet/stale adapters, enforce one active job and persist observations, and cancel bounded work. Headless Edge checked live passive inventory (2 adapters, 2 devices), one explicit live ICMP target (`192.168.1.94` from `.93`, timeout status 11010), then simulated responses/search/cancel/auto-scan with no further LAN traffic and no page errors. Screenshots inspected at `.runtime/settings-preview/scanner-passive.png`; other captures are `scanner-live.png` and `scanner-responsive.png`. No hostname/vendor/location is invented.

Still open:
- **Desktop parity:** full Protect application activity/sparklines, persistent searchable event journal, reload-interface action and route-metric gateway selection remain incomplete. DNS, link limits, Connected devices, OMR and retained offline adapter selection now have forms. Network Scanner now has passive neighbors, bounded source-bound discovery, progress/cancel, search, opt-in 60-second auto-scan and persisted observation history. Do not label this GUI DONE.
- **Desktop QA:** rendered traffic/Protect/network-selector screenshots inspected in `.runtime/go-widget-preview/`; native Go window is responsive. Interactive desktop tools still fail at initialization with sandbox-helper errors, so direct tray click/menu/toast/autostart/minimize/maximize/hide checks remain unverified. Headless Edge verified page/controls and live graph data.
- **Config location:** `.runtime/widget-config-path.txt` records the actual supervised daemon config path for default widget launches (currently in the previous session's temporary directory). Consolidate supervisor/widget config to a persistent workspace location before treating startup/reboot behavior as complete.

Run desktop: `start-widget.cmd`, or `build/gamebond-widget.exe -root . -config <client config>`. `-tray` starts hidden. `-print-url` prints the token-bearing local URL; `.runtime/widget-url.txt` contains the current development launch URL. Single instance per root. WebView2 is required; no Python process is used by this Go window. The Python UI files and rollback remain intact.

## 2. Cutover criteria and remaining evidence (ledger "Cutover criteria")

- **User correction:** a second physical adapter is NOT a prerequisite to validating the port. Validate single-link VPN operation on the available physical uplink; test bonding/path transitions with simulated additional paths. Preserve this requirement in the ledger.
- **Criterion 2:** extend real-daemon mixed-version/path-transition coverage where missing. One- and two-link Go daemon -> Python server framing/data checks pass; the new Go client socket test covers one -> two -> one usable paths. Existing failover probes remain evidence, with their documented limits.
- **Criterion 4:** sustained physical VPN operation can be validated on the available single uplink; multi-adapter physical measurements are additional evidence, not a prerequisite imposed on the user. The 600-second single-link soak passed (601.687 seconds, 38/38 checks, unchanged daemon PID/session, VPS exit IP and positive bidirectional packet deltas at every sample). Evidence: `evidence/single-link-go-soak-20261109.json` and `tools/soak_single_link_vpn.py`. This covers a ten-minute physical run, not multi-hour uptime or physical bonding.
- **Admin portal in a browser.** `POST /api/login` was verified with curl only (200, session cookie, CSRF token). The user should open `https://195.154.119.136:9444/` and log in. The password is in `.runtime/admin-password.txt` (git-ignored).
- **Unreviewed flakiness.** `client` TestPacedThroughputIsNotCappedByTimerGranularity fails under heavy CPU load (6591 of 20000 delivered); explained in the ledger as unrepaired loopback UDP loss, passes idle. `status` TestWriteJSONReplacesAtomicallyAndLeavesNoTemp is fixed (writer mutex, 30 of 30 runs).
- Then, only if every criterion holds: delete the Python code and the Python rollback release, and say so in the ledger.

## 3. Other ledger rows still PART/TODO

Read the ledger tables (sections 1 to 3 and 5). Several rows are PART with explicit "NOT done" notes (examples: `hwmon` daemon/admin surface, `omr_*`, `tty_server`, `atomic_io` adoption by `status`/`linkpolicy`/`scanner`, Linux hwmon backend). Section 5 lists Python tests that must be re-asserted in Go or retired deliberately. Drop decisions (TUN mode, `windows_network` routes/QoS, `windows_dns`, TUN-only launcher parts) were approved by the user on 2026-11-09 and are recorded in the ledger.

## 4. Live state to be aware of

- VPS 195.154.119.136: container `gamebond-server-1` runs `gamebond:native-a8492d9c4707` (release `/opt/gamebond/releases/native-a8492d9c4707`), Go edge with the Go admin portal on :9444. Older Go releases `native-17af65bdb4b8`, `native-c1f1488d9194`. The Python release remains for rollback. Deploy tool: `scratchpad/deploy_native.py` (prepare/swap/rollback).
- The admin password was reset this session; a backup of the old config is `configs/local-server.json.bak-pw` in the live release dir. A first attempt mangled the hash and the container was down for about 90 s; it was fixed.
- Local Go daemon runs supervised (config `scratchpad/client-selected.json`, single bind 192.168.1.93, interface 22). Control: `build/gamebond-ttyrelay.exe stop|restart -metadata .runtime/go-relay.json`. ProxiFyre capture list is `cod_executables` in the client config (includes System32 `curl.exe` for benchmarking).
- Benchmark evidence (Go about 4x the Python userspace client on the same link, and lower CPU) is in the git-ignored `evidence/` and summarised in the ledger (criterion 3).
