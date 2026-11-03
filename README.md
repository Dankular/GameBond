# GameBond

An original, experimental gaming tunnel for a Windows PC using two independent
IPv4 uplinks to one Linux VPS. The first profile targets Call of Duty through
explicit process DSCP tagging. It is **not ready to trust in a match yet**.

The default `start-client.cmd` now opens the userspace widget. Its Connect and
Disconnect controls manage the netstack/ProxiFyre backend without launching the
legacy elevated Wintun supervisor. The configured edge is `195.154.119.136:4433`.
The Windows Packet Filter driver must already be installed. The earlier TTY,
Windows routing and NRPT instructions below describe the legacy backend.

Use **Manage apps** in the widget to choose **All apps** (the default) or
**Selected apps only**, add executable files, and remove entries. Save and
reconnect to apply; existing application connections may need reopening.
This configures IPv4 application capture, with the tunnel carrier and helpers
excluded automatically. `capture_mode` stores `all` or `selected`; the selected
executable paths remain in `cod_executables` for compatibility. General UDP
traffic uses bulk scheduling; only the configured `game_udp_ports` receive
gameplay priority and replication.

The client includes a tray agent. Close the widget to hide it; click the tray
icon to reopen it. Its menu offers Connect/Disconnect, Manage apps, Network
settings, and **Quit (stop tunnel)**. Launching the client again shows the
existing agent instead of creating another one.

**Link roles & limits** configures each selected adapter as Primary, Secondary,
Backup, or Never, with separate upload/download ceilings and daily/monthly caps.
The client authenticates and synchronizes these policies with the VPS before
using a changed policy. The server must be updated to support policy negotiation.
Limits count encrypted tunnel wire bytes, including IPv4/UDP headers, duplicate
copies, control traffic and repairs. Usage persists in `.runtime/link-usage.json`;
monthly totals use the configured billing reset day. Cap enforcement follows
usage sampling and policy acknowledgement, so leave headroom for in-flight
traffic. Save and reconnect to apply configuration changes.

Project version **0.3.4** includes opt-in packet bonding for bulk traffic. Different
packets can use both uplinks while gameplay still sends immediate duplicate
copies. The first live CoD test confirmed DSCP46 tagging but exposed queue drops
and high RTT under load. Version 0.2 introduced immediate priority sends,
UDP-only CoD tagging and conservative bulk pacing; version 0.3 adds adaptive
per-path send budgets and bounded reordering for striped bulk packets.
Changing these project files does not upgrade a running endpoint. Local tests
are not physical 5G/Starlink latency or throughput measurements.

Version 0.3.3 also prioritizes received gameplay ahead of queued bulk, with
bounded admission that can evict bulk to protect a game packet. Logs expose
receive-class residence/drop counters, directional classification, priority
send/injection timing, and the owned Windows QoS policy readback. A TTY restart
reloads runtime source and configuration after cleanup. An older supervisor
must first be replaced by running the sole `start-client.cmd` as Administrator.

Version 0.3.4 charges each successful gameplay copy against its path's wire
service budget, leaving bulk the remaining pacing allowance. Gameplay still
sends immediately; this adds no capacity cuts or fixed percentage limit. Logs
include per-flow original/effective DSCP, classification reason, observed packet
gaps, per-path first/duplicate copies, and replay-window drops. Observed gaps
are not game packet-loss percentages.

IPv4 UDP fragments following a classified first fragment retain that policy
through a bounded, two-second association cache. This does not reassemble IP or
guess missing ports: an unmarked fragment arriving before its first fragment
remains unclassified, and its counter is exposed in telemetry.

## Project DNS overrides

The current client profile includes PeaCod's exact mapping:
`sat-wingdk-loginservice.prod.demonware.net` → `127.0.0.1`.
While the client runs, a bounded UDP/TCP responder listens only on its own TUN
address, `10.77.0.2:53`. Temporary exact-name Windows NRPT rules select it for
configured names. Other DNS servers, hosts files, certificates, and network
adapters' DNS settings are unchanged. Owned rules are removed before the
responder and TUN close; interrupted runs retain an ownership journal for the
next startup to recover. Existing exact-name rules are not overwritten.

```powershell
python -m gamebond dns show
python -m gamebond dns set sat-wingdk-loginservice.prod.demonware.net 127.0.0.1
python -m gamebond dns disable
python -m gamebond dns enable
python -m gamebond dns remove sat-wingdk-loginservice.prod.demonware.net
```

These commands edit only project configuration. Apply changes with a client
restart (`python -m gamebond.tty_server -restart` once the current supervisor is
installed). A/AAAA records support multiple addresses in JSON. The profile uses
TTL0; a configured IPv4-only name returns AAAA NODATA rather than forwarding it
to public DNS. Unknown names are refused unless an upstream is explicitly set.

DNS overrides do not start PeaCod or install TLS trust. Existing hosts entries,
cached answers and application-owned DNS can take precedence. In particular,
this workstation already has a PeaCod hosts entry; GameBond leaves it untouched,
so that entry continues to apply when GameBond stops.

Bonded endpoints must run matching implementations and agree on `bonding_mode`.
**Upgrade both ends and generate a fresh shared session before activating 0.3
bonding.** Do not change protocol or server mode during a match. There is no
automatic protocol negotiation or key rotation. Controlled client restart needs
the matching 0.3.2 server's authenticated sender-restart handshake. Older servers
still require a fresh shared session after client restart. Nonbonded mode retains
the GB01 wire format; bonded GB03 traffic fails closed against a GB01 endpoint.

| `bonding_mode` | `redundant_mode` | Behavior |
|---|---|---|
| `false` | `true` | Duplicate all traffic, including downloads. |
| `false` | `false` | Keep bulk flows on a healthy path; replicate configured queues. |
| `true` | `false` | Stripe nonreplicated packets across paths; replicate configured queues. |
| `true` | `true` | Rejected: full replication would prevent bulk striping. |

Existing configs without `bonding_mode` retain the previous default of `false`.
Both examples enable it and keep DSCP46 `priority: true` and `replicate: true`.
The bonding settings are:

```json
{
  "bonding_mode": true,
  "redundant_mode": false,
  "bonding_initial_rate_mbps": 1,
  "bonding_max_rate_mbps": 100,
  "reorder_timeout_ms": 30,
  "bulk_rate_mbps": 0
}
```

Initial and maximum rates are positive, finite per-path budgets; initial cannot
exceed maximum. Feedback adjusts the experimental path budgets. Maximum is a
ceiling, not a measurement of capacity or a promised aggregate throughput.
`bulk_rate_mbps: 0` removes the additional fixed application-wide cap; transport
path budgeting still applies in bonding mode. A positive value retains that cap.
Striped traffic has bounded receiver reordering with a 1–200 ms timeout, default
30 ms. A missing striped packet can delay bulk delivery up to that budget;
replicated gameplay bypasses this wait. Provider bufferbloat can still add delay.

Implemented:

- UDP packets encrypted and authenticated with ChaCha20-Poly1305; HKDF separates
  directions and sender instances. Random shared session IDs, bounded replay window.
- Immediate duplication over both uplinks and first-arrival gameplay delivery in
  each direction; optional packet striping and bounded reordering for bulk flows.
- Windows socket interface pinning, authenticated server path learning, probes,
  measured RTT, stale-path detection, and recovery while the process stays alive.
- DSCP queues with bounded capacity, maximum packet age, priority fairness,
  per-queue replication, and reverse-flow policy inheritance. CoD tagging must be
  verified on the installed game. No guessed port ranges are enabled.
- Windows Wintun client, Linux TUN server, IPv4 tunnel address checks, configured
  MTU, statistics, configuration checks, network setup scripts and loopback tests.

The protocol and source are ours. Decompiled Speedify pseudocode is held in
`evidence/`, separately from implementation. Speedify interoperability, licensing
services, and its server protocol are not implemented.

## Local validation

Python 3.11+ is required. This machine has Python 3.12 and cryptography 46.0.7.

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
python tools/measure_loopback.py
python -m gamebond --help
```

The measurement uses actual loopback UDP and synthetic send blackholes. See
`evidence/loopback-measurement.json`; these are not 5G/Starlink latency numbers.

## Prepare a session

1. Expose Starlink and the phone's USB tether as separate Windows adapters with
   separate IP addresses and gateways. The USB cable alone is insufficient; turn
   on **USB tethering**. Use `Get-NetAdapter`, `Get-NetIPAddress -AddressFamily
   IPv4`, and `Get-NetRoute -DestinationPrefix 0.0.0.0/0` to identify them.
2. Choose one static numeric VPS public IPv4 and allow UDP/4433 at its firewall.
   Use the same endpoint throughout the match. The VPS must support Linux TUN,
   IP forwarding and NAT. An installed Docker/Speedify server is not needed.
3. Copy the example configs to `configs/local-client.json` and
   `configs/local-server.json`. Replace all example addresses/indices. Ensure the
  client's source addresses match the selected physical adapter indices. Both
  ends must use the same bonding mode and client tunnel address.
4. Create the key in a private directory and distribute it to the VPS through
   your authenticated SSH connection:

   ```powershell
   New-Item -ItemType Directory secrets
   python -m gamebond keygen secrets/gamebond.key
   ```

   Put the printed session ID in **both** configs. It is not the secret key.
   Protect the key file with your OS account ACLs. Use a new session ID on both
   ends after an upgrade or server process restart. A persistent 0.3.2 supervisor
   can restart its client against a matching server using the authenticated
   sender-restart handshake; this does not rotate the shared key.
   Do not commit either live config or the key. `keygen` refuses to overwrite.
5. On Windows, the config requires an absolute path to a trusted, signed,
   architecture-matching Wintun DLL. The example refers to the existing installed
   Wintun library, which is a third-party driver. No proprietary Speedify daemon
   or UI is loaded by GameBond. Use an official Wintun distribution for deployment
   independent of Speedify and follow its redistribution terms.
6. Run `python -m gamebond check configs/local-client.json` and the corresponding
   server check. A check validates configuration syntax; it does not establish
   network reachability, correct adapter ownership or driver compatibility.

## Start the tunnel

The VPS endpoint is deployed separately from the existing WireGuard service, in
a Docker bridge namespace on UDP4433 on `178.104.238.86`. A project version bump
does not update the running Docker release; deploy matching artifacts explicitly.
The existing desktop WireGuard `.conf` and VPS `wg0` are preserved.

The server's Dockerfile/Compose configuration confines its TUN, forwarding and
NAT to the container. It uses `/dev/net/tun` and only `NET_ADMIN`, a read-only
root filesystem and key/config mounts; it has no host networking or privileged
mode. Docker manages the published UDP port through its ordinary bridge rules.
No separate host firewall, WireGuard or forwarding configuration is applied.

For another deployment, prepare matching configs/key and run on the server:

```text
docker compose --env-file deploy.env up -d --build
docker compose --env-file deploy.env ps
docker compose --env-file deploy.env logs --tail 30
```

`deploy.env` selects `GAMEBOND_SERVER_CONFIG=./configs/local-server.json` and
`GAMEBOND_KEY_FILE=./secrets/gamebond.key`. The container installs its own tools
during image build. Restart policy is deliberately disabled: generate a fresh
shared session on both ends after a server process restart. Do not run the standalone
`tools/linux-network.sh` on this Docker VPS; container startup owns those steps.

To start the client, disconnect Speedify/other VPN clients and use the launcher
whose private config matches the running server. Run it **as administrator**.
The general command is:

```text
python -m gamebond run CONFIG.json --key secrets/gamebond.key --configure
```

With `--configure`, the Windows client creates its own adapter and prepares only
its address/MTU and per-interface endpoint host routes. It waits for **both**
physical paths to authenticate before installing IPv4 tunnel routes and the
CoD UDP process QoS policies. Closing with Ctrl+C removes its own recorded settings.
Forced window closure can leave endpoint routes or policies. New runs retain
atomic ownership journals in `.runtime/network/` and recover stale records before
setup, refusing a live owner or hidden setup worker. Manual recovery is available
with `python -m gamebond.windows_network cleanup --journal PATH.json` in an
elevated terminal. `cleanup-old-client.cmd` handles the captured legacy routes
and narrowly identified old all-protocol CoD policies. No routing table is flushed.
The launchers open a separate Python console with a persistent supervisor.
Console stdout/stderr, including startup cleanup errors, are copied
asynchronously to a loopback log relay. An ordinary agent or non-elevated
terminal can monitor logs or request one of the three supported operations:

```text
python -m gamebond.tty_server attach --tail 100 --duration 30
python -m gamebond.tty_server -status
python -m gamebond.tty_server -stop
python -m gamebond.tty_server -restart
```

The relay binds only `127.0.0.1` on an ephemeral port. Its private access token is
in `.runtime/tty-session.json` and is not printed. Replay is bounded to 256 KiB;
at most eight attachments are accepted and slow readers are disconnected. The
publisher's bounded asynchronous queue drops log copies under pressure without
waiting on packet workers. Log attachments remain read-only. The separate
authenticated control role supports only stop, restart and status, with progress
and completed results. Stop waits for application/network cleanup and keeps the
elevated supervisor alive; restart cooperatively stops, cleans up, starts the
fixed configured client and waits for readiness. No shell, executable path or
arbitrary command can be supplied through this connection. Bootstrap of the
supervisor still requires legitimate Windows elevation; the relay does not grant
privileges. Only one registered supervisor can start an application instance.

No execution-policy setting is changed. DNS settings are left as configured by
Windows; confirm the selected DNS server is reachable through the chosen routing.

Run without `--configure` only if you are configuring addresses/routes yourself.
Existing VPNs may affect routing; inspect the resulting routes and use both
per-interface endpoint host routes. Never route the outer endpoint back into the
tunnel. Observe two healthy paths before routing game traffic.

The older standalone scripts remain an alternative for manual setup. Do not
combine them with automatic `--configure`. On Windows, review first (all
parameters are examples):

```powershell
.\tools\windows-network.ps1 -ServerIPv4 203.0.113.10 `
  -StarlinkIndex 21 -StarlinkGateway 192.168.1.1 `
  -FiveGIndex 57 -FiveGGateway 172.20.10.1
```

Use the actual game executable path, then add `-Apply` to execute. The script
adds endpoint host routes for both physical interfaces, a 1280-byte tunnel MTU,
IPv4 `/1` tunnel routes, and a process QoS policy for DSCP 46 if `GameExe` is
provided. The dedicated `tools/cod-profile.ps1` uses all three actual installed
CoD game executable paths from `configs/cod-profile.json`; review it, then use
`-Apply` to create those process policies and `-Undo` to remove them. These scripts
must be permitted by your Windows PowerShell execution policy; no policy is
changed by this project. The network script preflights collisions and attempts rollback on failure. Review its
printed cleanup commands. These are active-session settings, not a boot service.

Verify DSCP 46 on the inner game packets with an authorized local packet capture;
do not assume the launcher executable or a policy name proves game tagging.
Return packets inherit the queue policy in the application; their IP headers are
not rewritten. Outer encrypted UDP does not expose DSCP. With `redundant_mode`
true, all tunneled traffic is duplicated, including downloads. Set it false on
both ends for selective queue replication; it must be false with bonding enabled.
UDP3075 was observed in the local CoD installation and is explicitly configured
in the examples; it is not a universal CoD port assumption.

## Limits that still need work

- Controlled physical 5G/Starlink/VPS interruption tests, sustained bonded
  throughput measurements and another controlled live CoD test remain necessary.
  Neither a loopback test nor a decompilation can guarantee game continuity.
- IPv4 forwarding only. The classifier parses IPv6 DSCP but the runner rejects
  IPv6. IPv6 traffic is not captured by these routes; this is not a complete
  privacy VPN or kill switch. Validate the game's real address family.
- One client/session per server process. No forward secrecy, automatic key
  rotation, validated physical server-restart continuity, service installer, or dynamic
  path MTU discovery. Adaptive packet bonding is experimental and needs testing
  under loss, unequal delays and changing radio capacity. Its rate ceiling is
  not a bandwidth measurement or a fairness guarantee. Configure physical MTUs
  for inner MTU + 89 bytes, or **+113 bytes with bonding enabled**. Inner MTU1280
  therefore needs 1393 bytes for bonded outer packets.
- `retransmissions: 0` is the only accepted setting. Nonzero values fail rather
  than silently claiming recovery. Gameplay uses redundant copies without ARQ;
  Bonded TCP also has experimental selective repair: authenticated gap requests,
  at most two retries, a one-second cache, at most 2,048 cached packets of at most
  2,048 bytes, and a paced repair queue of at most 64 requests. Repair shares
  normal bulk pacing/window credit. UDP gameplay has no ARQ. TCP retains its
  own retransmission; no forward error correction or proven physical-link
  throughput improvement is claimed for this experiment.
- Queue age limits apply to application queues; they cannot remove bufferbloat
  already present in a phone, router or provider. Priority game traffic remains
  replicated at its offered rate; process UDP tagging may include more traffic
  than a particular gameplay flow.
- Unit tests use fake TUN devices and real loopback UDP, including a bonded
  full-MTU round trip. They do not establish physical aggregation or game latency.

## Reverse-engineering evidence

See [docs/reconstruction.md](docs/reconstruction.md) for the target identity,
Evidence IDs, coverage and full-export workflow. Pseudocode is not the original
source and does not recover the remote Speedify service. Open questions remain
explicit even when an entire discovered function inventory has been attempted.

Official implementation references:
[Wintun API](https://github.com/WireGuard/wintun/blob/master/README.md),
[Linux TUN interface](https://docs.kernel.org/networking/tuntap.html),
[Windows IP_UNICAST_IF](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options).
