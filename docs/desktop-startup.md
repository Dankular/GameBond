# Go desktop startup

`start-widget.cmd` and `start-client.cmd` open `build/gamebond-widget.exe`.
The desktop reads `configs/local-desktop.json` to find its persistent client
config, shared key and netstack helper. Opening the desktop or polling status
does not start a tunnel. With a valid profile and no supervisor, the desktop
shows Disconnected and enables Connect.

Connect reuses the registered supervisor when its config matches. Otherwise,
when the relay is absent, it validates the profile and files, starts the Go
client with `-supervise -stopped`, waits for that process to register, and sends
one authenticated restart. The supervisor remains available after Disconnect.
The profile's `proxifyre` flag explicitly opts into application capture on
Connect. No packet-filter adapter is opened during supervisor bootstrap.

Copy `configs/desktop.example.json` to `configs/local-desktop.json` and set:

- `config`: the configured client JSON, normally `configs/local-client.json`.
- `key`: the 32-byte binary shared key file, without embedding it in JSON.
- `netstack`: the built netstack executable.
- `proxifyre`: whether Connect should start application capture.

Paths resolve against `-root`, including when launched from the Windows Run
entry with a different working directory. Client, status, relay, usage and
application-history arguments are absolute. Start with Windows retains the
root, selected config and launch-profile path using Windows argument quoting.
Enabling autostart opens the desktop at login; it does not connect the VPN.

Build and inspect from PowerShell:

```powershell
$env:GOFLAGS='-buildvcs=false'
Set-Location native-edge
go build -o ../build/gamebond-native-client.exe ./cmd/client
go build -o ../build/gamebond-desktopctl.exe ./cmd/desktopctl
go build -ldflags '-H=windowsgui' -o ../build/gamebond-widget.exe ./cmd/tray
Set-Location ..
build/gamebond-desktopctl.exe check -root .
build/gamebond-desktopctl.exe status -root .
build/gamebond-desktopctl.exe ensure -root .
```

`check` validates files/config without launching anything. `ensure` starts or
reuses a supervisor and never sends restart. `connect` and `stop` perform their
named VPN actions. Startup errors go to `.runtime/supervisor.log`. Relay
metadata includes the config path, uses atomic replacement and shared reads,
and has an OS file lease to prevent two relays taking the same metadata path.
A live legacy relay is also detected. A live relay without a registered owner
is reported explicitly rather than replaced.

The workstation was migrated on 2026-11-09. Its actual profile references
`secrets/edge195.key`, the attribution netstack and application capture. The
previous persistent config and the original temporary config were backed up
locally before migration. Dangling second-adapter ID/name/gateway entries were
removed to match its one selected link. No PS5 gateway was activated.

Verification covers an actual cold widget start with no supervisor, enabled
Connect without process creation, a real stopped-supervisor bootstrap, matching
config identity and unchanged legacy netstack processes. Cold Connect through
the rendered widget then created a new Go supervisor and a physical single-link
VPN: captured curl exited at `195.154.119.136`, with 12 outbound and 10 injected
packets during the check. Disconnect returned to stopped. The evidence is
`evidence/desktop-startup-20261109.json` (local/ignored). Manager integration
tests exercise first Connect/restart/stop through a real authenticated relay
and a synthetic session. Autostart command parsing and enable/disable storage
are tested in an isolated HKCU key. Native tray-menu interaction, actual Windows
login/reboot remain unverified; the connection was left stopped. The CLI was
also checked from `C:/Windows/System32` with an explicit workspace root.
