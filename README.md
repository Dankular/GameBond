# GameBond

An experimental Windows connection-bonding client and Linux VPS server.
Stripes bulk traffic across IPv4 uplinks and duplicates selected traffic for resilience.

## Features

- Run as a VPN with one uplink; bond traffic when multiple uplinks are active (up to 8).
- All-app or selected-app capture, with application traffic profiles.
- Adaptive redundancy, link roles, speed limits, and usage caps.
- Dashboard and tray controls for connection health and app traffic.
- Connected devices: a console on a spare (USB) adapter gets its own bond address ([setup](docs/lan-devices.md)).
- Loss resilience: reorder buffer, TCP repair, parity FEC, adaptive duplication and loss steering.
- Fast failover: BFD path detection (~300 ms), fast reroute, ECMP-style flow pinning.
- Queueing: per-flow fair queue with CoDel and ECN marking, DSCP classes.

The full list with config flags is in [FEATURES.md](FEATURES.md).

## Client

Windows, with ProxiFyre and the Windows Packet Filter driver. This is a source
checkout; there is no installer. Everything is Go (Go 1.25+); Python is not used.

```powershell
$env:GOFLAGS = "-buildvcs=false"
go -C native-edge build -o ../build/gamebond-native-client.exe ./cmd/client
go -C native-edge build -o ../build/gamebond-desktopctl.exe ./cmd/desktopctl
go -C native-edge build -ldflags "-H=windowsgui" -o ../build/gamebond-widget.exe ./cmd/tray
go -C netstack build -o ../build/gamebond-netstack.exe .
.\start-widget.cmd
```

Configure `configs/local-client.json` from [the example](configs/client.example.json).
Optional transport flags (`failover_replay`, `flow_pinning`, `codel`, `loss_tracking`, `delay_control`)
are described in [FEATURES.md](FEATURES.md); set the same ones on the server.
Choose **Connect** in the widget. Closing the window hides it in the tray;
**Quit (stop tunnel)** exits. `build\gamebond-desktopctl.exe status|ensure|connect|stop -root .`
controls the supervisor from a shell. Rebuild `desktopctl` and the widget whenever
config validation changes, because they embed the validators.

For several Starlinks, see [multiple uplinks](docs/multiple-uplinks.md).
For a PS5, laptop or phone behind a USB adapter or a Wi-Fi access point on it,
see [connected devices](docs/lan-devices.md).

## Desktop walkthrough

Start the widget with `start-widget.cmd`. The status strip at the top shows each
uplink (adapter, address, live rates, Starlink dish and Wi-Fi signal where
available) and a chip for every connected device. The **Connect/Disconnect**
button starts and stops the tunnel. The footer shows the exit server and link count.

**Traffic Monitor** is the home page. It graphs live adapter traffic (or VPN-only
counters) per application or for everything, over a selectable window.

![Traffic Monitor](docs/screenshots/traffic.png)

**Applications & hosts** lists what each app is talking to.

![Applications and hosts](docs/screenshots/traffic-apps.png)

**Issues** is the health page: per-link loss, jitter and RTT, packets the receiver
gave up on, bursts and stalls, and the PS5 gateway probe loss. Start here when a
game feels bad.

![Issues](docs/screenshots/issues.png)

**Protect** controls which applications use the tunnel. All traffic is included by
default (unverified applications are allowed). Per app you can allow or block, set a
traffic profile, and see hosts and rates.

![Protect](docs/screenshots/protect.png)

**Log Analysis** is the event journal: connection changes and first-seen apps, with
filters and read markers.

![Log Analysis](docs/screenshots/logs.png)

**Network Scanner** reads the local neighbour cache per adapter and can run a
bounded ICMP scan of a private subnet. It never probes without being asked.

![Network Scanner](docs/screenshots/scanner.png)

**Hardware Resources** shows CPU, memory, GPU and network load on the PC.

![Hardware Resources](docs/screenshots/hardware.png)

The buttons under the uplink strip open dialogs:

- **Select networks** chooses which adapters are bonded (1 to 8).

  ![Select networks](docs/screenshots/networks.png)

- **Link roles & limits** sets each link's role (primary, secondary, backup, never),
  speed limits and daily/monthly caps.

  ![Link roles and limits](docs/screenshots/links.png)

- **Connected devices** gives a console, laptop or phone its own bond address. Several
  devices can share one adapter, for example a router in access-point mode on a
  USB Ethernet adapter. See [lan-devices.md](docs/lan-devices.md).

  ![Connected devices](docs/screenshots/devices.png)

- **OpenMPTCProuter** optionally sends non-game traffic through an OMR server.

  ![OpenMPTCProuter](docs/screenshots/omr.png)

Screenshots mask public IP and MAC addresses.

## Server

Requires Linux, Docker Compose, and `/dev/net/tun`.

1. Copy [the server example](configs/server.example.json) to `configs/local-server.json`.
2. Create a 32-byte key: `head -c 32 /dev/urandom > secrets/gamebond.key`.
3. Configure matching keys, session IDs, and bonding settings on both endpoints.
4. Set `GAMEBOND_SERVER_CONFIG=./configs/local-server.json` and
   `GAMEBOND_KEY_FILE=./secrets/gamebond.key` in `deploy.env`.

```sh
docker compose --env-file deploy.env up -d --build
docker compose --env-file deploy.env logs --tail 30
```

The Go edge owns TUN/NAT inside its container and publishes UDP 4433. Addresses
for attached LAN devices go in the server config as `lan_tunnel_ips`.
Keep keys and live configs private. Server restarts require matching session handling.

An optional HTTPS admin portal (status, config editing, restart) is described in [admin-portal.md](docs/admin-portal.md).

## Fragmentation and the 1280 MTU (read this before debugging game loss)

The tunnel MTU is 1280. Internet hosts, game servers in particular, send
packets of 1280-1500 bytes with the Don't Fragment (DF) bit set. A Linux router
must drop those instead of fragmenting them, and returns an ICMP "fragmentation
needed" that games ignore. The result is silent loss of exactly the big packets:
hits, kills and kill-cam data.

What we saw (2026-11-10, COD on a PS5 through the tunnel):
- In-game packet loss of 12-33% when getting hit, while movement was fine.
- Every tunnel counter showed 0% loss, so the loss was invisible on the legs.
- About 18% of inbound game packets were over 1280 bytes with DF set. The server
  sent ICMP type 3 code 4 to the game servers at its rate limit of 1/s each.
- Going direct (`udp_direct`) had no loss because nothing there is limited to 1280.
- Time was lost on queue limits, classifier tags, reorder timers and the exit route.
  None of them was the cause.

Fix: the container entrypoint (`tools/container-entrypoint.sh`) adds an nft
chain `ip gamebond defrag` that clears DF on inbound packets over 1280 bytes. The
kernel then fragments them to fit the tunnel and the PS5 reassembles them.
Every server image must use this entrypoint. If you swap the base image, keep
the rule, and check that it survived with:

```sh
docker exec <container> nft list chain ip gamebond defrag
```

How to check for the problem in about a minute: on the server, capture inbound
UDP on the public interface and count packets with total length over 1280 and
DF set. Also count outbound ICMP type 3 code 4. Both should be zero on a
healthy server. Pings to game servers tell you nothing, because they do not
answer ICMP.

The client's LAN gateway fragments oversized device packets without DF, and
sends ICMP frag-needed for DF ones. Watch `oversize_fragmented` and
`oversize_df_dropped` in the status file.

## Development

```powershell
$env:GOFLAGS = "-buildvcs=false"
go -C netstack test ./...
go -C native-edge test ./...
```

- [netstack/](netstack/): Windows userspace proxy.
- [native-edge/](native-edge/): the Go client, server edge, widget and tools.
- [native-edge/testdata-gen/](native-edge/testdata-gen/): frozen Python scripts that generated the test vectors. Python is not needed to run the tests.
- [tools/](tools/): container entrypoint, deploy and diagnostic scripts.

The Python implementation was retired; it remains in git history.
GameBond uses its own protocol and does not interoperate with Speedify.
