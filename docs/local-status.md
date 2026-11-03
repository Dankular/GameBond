# Local state observed 2026-11-02

The phone initially enumerated as `AppleUSBEthernet` with Windows problem code
28 and no driver INF. The iPhone USB and portable-device functions were healthy.
The installed Microsoft Store iTunes package had no Ethernet driver INF, and
the conventional `Common Files/Apple` folders were absent.

The matching Apple Ethernet driver was obtained from Microsoft Update Catalog.
Its catalog signature verified as Microsoft Windows Hardware Compatibility
Publisher, and its INF includes the actual device's hardware ID. After the
`pnputil /add-driver ... /install` attempt (which reported the package already
present as `oem123.inf`), the device was verified healthy, `Netaapl` running,
and the network adapter active. See `evidence/iphone-driver-repair.json` for
the source, SHA-256 and precise command outcome.

| Path | Windows adapter | Index | Local IPv4 | Gateway |
| --- | --- | --- | --- | --- |
| Starlink | Ethernet / Realtek Gaming GbE | 21 | 192.168.1.93 | 192.168.1.1 |
| iPhone | Ethernet 3 / Apple Mobile Device Ethernet | 57 | 172.20.10.2 | 172.20.10.1 |

Speedify's read-only adapter query subsequently reported both connected. It
reported Starlink's working priority as backup and the phone's as secondary;
these settings were not changed by this project. Its current connection was
active with IP-leak protection enabled. Direct HTTPS connections explicitly
pinned and bound to each physical path were rejected locally with WinError10013
at connect, so independent internet reachability was not established in this
agent session. This does not invalidate the repaired device enumeration.

The selected VPS is `178.104.238.86`, with existing WireGuard `wg0` on UDP51820.
Its SSH host key matched the existing OpenSSH known_hosts entry, and the
user-supplied PPK authenticated successfully. Docker29.6.1, Compose5.2.0 and
`/dev/net/tun` were already available. GameBond was built and started as
`gamebond-server-1` on UDP4433 in the dedicated `gamebond_tunnel` bridge network.
Release: `/opt/gamebond/releases/5fbd6b092d1dfc85849a92eb4a286092`.

Existing WireGuard and other containers were not reconfigured. No host packages,
manual host NAT/firewall/forwarding changes or Docker pruning were performed.
The container owns TUN, forwarding and NAT inside its own network namespace.
Docker's normal port publishing adds its own bridge rules. The original desktop
WireGuard config was read only for non-secret connection fields and was not edited.

Matching local client/server configs now exist under `configs/local-*.json`,
with a separately generated key in `secrets/gamebond.key`; neither is part of
the image build context. No GameBond Windows route or QoS policy has been applied.
Recheck interface addresses/indices after reconnection. CoD is installed under
`C:\XboxGames\Call of Duty`; its three observed game executable paths are retained
in `configs/cod-profile.json`, pending active-match DSCP verification.

The native Docker smoke passed: encrypted duplicate packets were delivered once,
the TUN returned ICMP, and container NAT returned an internet DNS response.
The PC subsequently reached public UDP4433 through its current VPN routing and
received TUN ICMP (40.787ms) and internet DNS (77.6ms). See the separate validation
JSON files in `evidence/`. That public test was single-path and did not measure
5G/Starlink separately. GameBond was then restarted with a fresh shared session
matching the local configs; the actual game client has not yet connected.

The installed Wintun DLL signature verified as WireGuard LLC. Opening a temporary
GameBond QA adapter from this agent failed with WinError5 (Access denied), and
no GameBond adapter remained afterward. `start-client.cmd` requires Run as
administrator and uses `--configure`: both physical paths must authenticate
before IPv4 tunnel routes and per-process CoD QoS are activated. Host DNS and
IPv6 settings are not changed. A live Windows and CoD test is still required.
# Historical status: 0.3.2, 2026-11-02

GameBond 0.3.2 is healthy in its isolated Docker container on 138.199.201.16. The current client config targets that host, deployed module hashes match, and 113 local tests pass. See [findings.md](../findings.md) for the live controller failures and subsequent offline corrections.

The user started the updated client successfully. TTY status confirms supervisor PID 23084 is running, with both physical paths healthy and connected to 138.199.201.16. A subsequent relay snapshot shows both pacing budgets at 1 Mbps, zero delay backoffs, empty queues, and no authentication, socket, receive-queue or bonding-deadline errors. Starlink has three packet expirations without a capacity collapse. This light-traffic observation does not measure aggregate throughput or gameplay latency. There is one start entry point, `start-client.cmd`.

## Current status: 0.3.4, 2026-11-02 14:32 UTC

The final 0.3.4 image is healthy on 138.199.201.16. All 13 checked module hashes match the local sources; 171 local tests passed. Deployment evidence is in [update-0.3.4.json](../evidence/update-0.3.4.json). Shared physical service accounting, fragment priority association, fresh telemetry and scoped PeaCod DNS management are implemented; see [findings.md](../findings.md) for measured results and limitations.

The Windows client is currently stopped: fresh TTY status reports no supervisor owner. Older relay samples are historical. This agent's Windows elevation attempt failed with 0xc0000142; a fresh Administrator launch of the sole `start-client.cmd` entry point is required before effective QoS, NRPT activation and physical gameplay continuity can be verified. No live improvement is claimed from offline tests. The existing PeaCod hosts entry remains untouched and continues to apply with GameBond off.

### Follow-up at 14:55 UTC

The client is now running under supervisor PID3808 with both links healthy. A live-discovered lowercase NetQos name mismatch was corrected in verification and cleanup; 27 stale GameBond policies were removed and all three current game UDP/DSCP46 policies verified. The effective NRPT lookup now enumerates and filters exact names, avoiding the provider's absent-namespace error. Full validation passes 172 tests. These Windows-only fixes do not require restarting the VPS.

PeaCod DNS works over TCP. UDP responses still fail in a standalone source-port53 loopback echo despite successful socket sends; ephemeral-port echo works. The filtering cause remains undetermined. No global firewall/service/DNS settings were changed. CoD physical-outage continuity remains unverified.

