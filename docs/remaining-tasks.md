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
superseded by this update. Scanner and journal follow-ups are recorded below; other listed gaps remain open.

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
- **Single physical link:** `tools/check_single_link_vpn.py` verified exit IP 195.154.119.136 and increasing outbound/injected counters with one healthy Go path; evidence is `evidence/single-link-vpn.json` (git-ignored). The check uses shared Windows file reads with bounded retry. That was the earlier running session; section 4 records the latest state.

Scanner verification (2026-11-09): `go test ./...` passes on Windows. Endpoint tests prove passive reads send no probes, reject public/off-subnet/stale adapters, enforce one active job and persist observations, and cancel bounded work. Headless Edge checked live passive inventory (2 adapters, 2 devices), one explicit live ICMP target (`192.168.1.94` from `.93`, timeout status 11010), then simulated responses/search/cancel/auto-scan with no further LAN traffic and no page errors. Screenshots inspected at `.runtime/settings-preview/scanner-passive.png`; other captures are `scanner-live.png` and `scanner-responsive.png`. No hostname/vendor/location is invented.

Event journal verification (2026-11-09): `eventjournal` ports the version-1 `.runtime/dashboard-events.json` file, first-use deduplication (including existing Python integer timestamps/Unicode paths), connection transitions, read markers and bounded history. One asynchronous writer coalesces pending snapshots and flushes on graceful exit; corrupted originals stay intact with a visible error. Background sampling ingests events even while the widget is hidden. Go tests cover restart/read-state persistence, corruption, transitions, limits and a blocked writer retaining only the latest snapshot. Log Analysis now has kind/period/search filters, grouped date cards and Mark all as read; cards are reused and bounded to 512 cached entries/256 visible events. Edge checks used the real journal (32 events) plus simulated filter/read/card-reuse cases, zero page errors; screenshot `.runtime/settings-preview/journal.png` inspected. `go test ./...` passes on Windows.

Protect/reload/gateway follow-up (2026-11-09): background Go `AppActivitySampler` merges verified process generations by canonical executable path, measures rates from status timestamps, suppresses first/reset/stale/repeated samples and retains 60 points per app. Protect now shows inbound scope, outbound controls, version, hosts, rates and sparklines alongside configured-only rows, search, rule mode, selection/profile editing and application details. Node/Edge UI checks used simulated status and an isolated actual config: controls/canvas/selection were reused, graphs painted, block/profile/protection edits persisted, search worked, disconnect removed activity while retaining its saved rule. Screenshot `.runtime/protect-preview/protect.png` inspected, no page errors. Unit tests cover counter/process/session resets, duplicate samples, aggregation, invalid counters, pruning and bounded background history. Interface reload dispatch/fallback tests sent zero VPN control requests; actual native WebView reload interaction remains part of desktop QA. Windows gateway discovery reads the default-route table and selects the lowest route metric per adapter; ties are deterministic and interface metric is added for display. Real read-only discovery matched Windows (`Ethernet 22`, `192.168.1.1`, route offset 0 + interface metric 25). No route writes. Full Windows `go test ./...` and Linux dashboard build pass.

Still open:
- **Desktop parity:** Protect application activity/sparklines, interface reload and metric-selected gateways are now implemented and checked as recorded below. Native interaction/toast/autostart, startup consolidation and the broader ledger gaps remain open. Native inspection was retried this turn: trusted Node process exited during both initialization attempts. DNS, link limits, Connected devices, OMR and retained offline adapter selection now have forms. Network Scanner now has passive neighbors, bounded source-bound discovery, progress/cancel, search, opt-in 60-second auto-scan and persisted observation history. Do not label this GUI DONE.
- **Desktop QA:** rendered traffic/Protect/network-selector screenshots inspected in `.runtime/go-widget-preview/`; native Go window is responsive. Interactive desktop tools still fail at initialization with sandbox-helper errors, so direct tray click/menu/toast/autostart/minimize/maximize/hide checks remain unverified. Headless Edge verified page/controls and live graph data.
- **Config/startup implementation verified:** widget and supervisor now share `configs/local-client.json` through `configs/local-desktop.json`; `.runtime/widget-config-path.txt` points to that persistent config. Actual no-supervisor UI start offered enabled Connect without creating a process. Cold Connect then bootstrapped a new Go supervisor, proved VPS exit IP and bidirectional counters on one physical link, and Disconnect returned to stopped. CLI check/status also pass from System32 with an explicit root. Native tray/autostart interaction and an actual Windows login/reboot remain unverified. See `docs/desktop-startup.md`.

Run desktop: `start-widget.cmd`, or `build/gamebond-widget.exe -root . -config <client config>`. `-tray` starts hidden. `-print-url` prints the token-bearing local URL; `.runtime/widget-url.txt` contains the current development launch URL. Single instance per root. WebView2 is required; no Python process is used by this Go window. The Python UI files and rollback remain intact.

Startup verification (2026-11-09): `desktopruntime` and `cmd/desktopctl` validate a persistent launch profile, reuse a matching authenticated supervisor, and create only a stopped supervisor before explicit Connect. Status/Stop never spawn. Unreachable known processes are not falsely reported stopped; config mismatch and live ownerless relays fail explicitly. Relay metadata has an OS file lease, atomic writes and shared reads. Tests cover duplicate/legacy relay protection, stopped bootstrap, first Connect/restarts/stop, invalid keys, config mismatch, unconfirmed stop and unrelated PID reuse. Real cold Connect through the rendered widget created PID 31396, reached one healthy physical path, and captured curl exited at 195.154.119.136 (12 outbound / 10 injected packet deltas). Disconnect confirmed stopped. Evidence: `evidence/desktop-startup-20261109.json`; screenshot `.runtime/protect-preview/cold-start.png` inspected. Original config/binary backups are in `.runtime/desktop-migration/` and `configs/local-client.pre-desktop.json`; unused second ID/name/gateway entries were removed to match the sole selected uplink. Autostart command quoting/profile retention and isolated HKCU storage tests pass; no real startup setting was changed. Full Windows Go suite and Linux edge/desktop builds pass. Python `ensure_server`, read/attach/control functions recognize the Go relay without spawning Python. Native-window and actual login/reboot QA remain open.

## 2. Cutover criteria and remaining evidence (ledger "Cutover criteria")

- **User correction:** a second physical adapter is NOT a prerequisite to validating the port. Validate single-link VPN operation on the available physical uplink; test bonding/path transitions with simulated additional paths. Preserve this requirement in the ledger.
- **Criterion 2:** extend real-daemon mixed-version/path-transition coverage where missing. One- and two-link Go daemon -> Python server framing/data checks pass; the new Go client socket test covers one -> two -> one usable paths. Existing failover probes remain evidence, with their documented limits.
- **Criterion 4:** sustained physical VPN operation can be validated on the available single uplink; multi-adapter physical measurements are additional evidence, not a prerequisite imposed on the user. The 600-second single-link soak passed (601.687 seconds, 38/38 checks, unchanged daemon PID/session, VPS exit IP and positive bidirectional packet deltas at every sample). Evidence: `evidence/single-link-go-soak-20261109.json` and `tools/soak_single_link_vpn.py`. This covers a ten-minute physical run, not multi-hour uptime or physical bonding.
- **Admin portal browser gate passed (2026-11-09):** `node tools/check_admin_browser.cjs --output evidence/admin-browser-20261109.json` logged in with the labelled password from `.runtime/admin-password.txt`, rendered Overview plus ten read-only pages, checked Secure/HttpOnly/SameSite=Strict session flags and logged out. Zero page errors. Overview/Connected Devices screenshots were inspected; captures are in `.runtime/admin-browser/`. Self-signed TLS was accepted for the test; certificate-chain trust was not asserted. No config/password/restart action was submitted.
- **Unreviewed flakiness.** `client` TestPacedThroughputIsNotCappedByTimerGranularity fails under heavy CPU load (6591 of 20000 delivered); explained in the ledger as unrepaired loopback UDP loss, passes idle. `status` TestWriteJSONReplacesAtomicallyAndLeavesNoTemp is fixed (writer mutex, 30 of 30 runs).
- Then, only if every criterion holds: delete the Python code and the Python rollback release, and say so in the ledger.

## 3. Other ledger rows still PART/TODO

Read the ledger tables (sections 1 to 3 and 5). Several rows are PART with explicit "NOT done" notes (examples: `hwmon` daemon/admin surface, `omr_*`, `tty_server`, `atomic_io` adoption by `status`/`linkpolicy`/`scanner`, Linux hwmon backend). Section 5 lists Python tests that must be re-asserted in Go or retired deliberately. Drop decisions (TUN mode, `windows_network` routes/QoS, `windows_dns`, TUN-only launcher parts) were approved by the user on 2026-11-09 and are recorded in the ledger.

## 4. Live state to be aware of

- VPS 195.154.119.136: container `gamebond-server-1` runs `gamebond:native-a8492d9c4707` (release `/opt/gamebond/releases/native-a8492d9c4707`), Go edge with the Go admin portal on :9444. Older Go releases `native-17af65bdb4b8`, `native-c1f1488d9194`. The Python release remains for rollback. Deploy tool: `scratchpad/deploy_native.py` (prepare/swap/rollback).
- The admin password was reset this session; a backup of the old config is `configs/local-server.json.bak-pw` in the live release dir. A first attempt mangled the hash and the container was down for about 90 s; it was fixed.
- Latest observed local state (2026-11-09 20:15 UTC): Go supervisor PID 31396 reports `stopped` after the cold Connect/Disconnect test; no active session children remain. It uses persistent `configs/local-client.json` and all-absolute launch arguments from `configs/local-desktop.json`. The six pre-existing netstacks (300, 1084, 6828, 9104, 14620, 17368) remain. The test widget was closed after verification; the updated build is installed at `build/gamebond-widget.exe`. `start-widget.cmd` opens it without automatically connecting. Autostart was off and remains off. Control: `build/gamebond-desktopctl.exe status|ensure|connect|stop -root .`.
- Benchmark evidence (Go about 4x the Python userspace client on the same link, and lower CPU) is in the git-ignored `evidence/` and summarised in the ledger (criterion 3).

## Python retirement (2026-11-11)

The Python code (`gamebond/`, `tests/`, `tools/*.py`, `pyproject.toml`) was removed at the user's
request after the Go client and edge were running live. It is in git history. The vector generators
are frozen in `native-edge/testdata-gen/`. The root `Dockerfile` now builds the Go edge and the
entrypoint no longer needs Python. The VPS Python rollback release was not touched. The ledger
statuses above describe the state at migration time.
