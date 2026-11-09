# Remaining tasks: Python to Go migration

Goal (still active): feature parity of the Python codebase in Go, then retire Python entirely.
**Status: NOT met. Do not delete any Python code or the Python rollback release until every cutover criterion holds.**

Source of truth is `docs/go-migration-ledger.md`. Update the ledger in the same commit as any row change.
All work so far is committed locally; nothing is pushed (do not push without being asked). Latest commit when this was written: `3f936dd`.

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

Decision (user): PORT, as a Windows tray agent plus a local web dashboard served by Go. Built and running: `native-edge/tray`, `cmd/tray`, `native-edge/dashboard` (panels: status, links, per-app traffic, link roles and limits, captured-app list, DNS, adapters read-only, hardware and GPU, log tail, wire-rate graph), tray balloon toasts, a "Start with Windows" item.

Not ported:
- **Per-app policy editor.** Was starting this when interrupted. The Python config keys are `protection_enabled`, `default_app_profile` and `app_rules` (path to `{outbound: allow|block, profile}`), validated by `apppolicy.New` / `NormalizeRules` in `native-edge/apppolicy/policy.go`. Add `/api/app-policy` to `dashboard/dashboard.go` using the existing `(*Server).section` helper, a panel in `dashboard/index.html`, and tests in `dashboard/dashboard_test.go`.
- **Adapter selection from the dashboard.** Currently read-only. Needs gateway discovery (the Python `windows_network` logic) to write `bind`, `interface_indices`, `gateways`.
- **Qt look and widget** (`glass_*.py`, `widget.py`, `widget_data.py`, about 4,100 lines): no Go equivalent. Decide how far to go (styled dashboard versus a native widget window).
- Not seen by eye: the dashboard page in a browser, the tray icon and menu, the toasts, the autostart item. There was no screenshot tool.
- Minor parity gap: the daemon's `linkpolicy` ignores unknown policy fields, unlike Python. The dashboard compensates with a `knownFields` check.

Running tray: `build/gamebond-tray.exe -root . -config <client config> -print-url`. The dashboard URL contains the access token and is printed to stdout (the last one is in `scratchpad/tray5.out`). Single instance per root.

## 2. Cutover criteria still open (ledger "Cutover criteria")

- **Criterion 2, real-daemon failover.** Go and Python daemons through a cut on a real second path. Needs the second adapter (hotspot 172.20.10.2, currently absent). Go-to-Go loopback failover and the mixed Go client to Python server failover are already verified (`tools/check_go_failover.py`).
- **Criterion 4, multi-uplink physical soak.** Also needs the second adapter.
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
