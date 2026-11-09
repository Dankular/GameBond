# GameBond

An experimental Windows connection-bonding client and Linux VPS server.
Stripes bulk traffic across IPv4 uplinks and duplicates selected traffic for resilience.

## Features

- Run as a VPN with one uplink; bond traffic when multiple uplinks are active (up to 8).
- All-app or selected-app capture, with application traffic profiles.
- Adaptive redundancy, link roles, speed limits, and usage caps.
- Dashboard and tray controls for connection health and app traffic.
- Connected devices: a console on a spare (USB) adapter gets its own bond address ([setup](docs/lan-devices.md)).

## Client

Requires Python 3.11+, ProxiFyre/Windows Packet Filter, and built Go helpers.
This is a source checkout; a packaged installer is not available.

```powershell
python -m pip install -e ".[widget]"
.\start-client.cmd
```

Configure `configs/local-client.json` from [the example](configs/client.example.json).
Choose **Connect** in the dashboard. **Manage apps** controls capture;
**Link roles & limits** controls uplinks. Reconnect after settings changes.
Closing the window hides it in the tray; **Quit (stop tunnel)** exits.

For several Starlinks, see [multiple uplinks](docs/multiple-uplinks.md).
For a PS5 or other device on a USB adapter, see [connected devices](docs/lan-devices.md).

The default uses a userspace network stack. Administrator/Wintun commands
belong to a separate legacy backend.

## Server

Requires Linux, Docker Compose, and `/dev/net/tun`.

1. Copy [the server example](configs/server.example.json) to `configs/local-server.json`.
2. Generate a key: `python -m gamebond keygen secrets/gamebond.key`.
3. Configure matching keys, session IDs, and bonding settings on both endpoints.
4. Set `GAMEBOND_SERVER_CONFIG=./configs/local-server.json` and
   `GAMEBOND_KEY_FILE=./secrets/gamebond.key` in `deploy.env`.

```sh
docker compose --env-file deploy.env up -d --build
docker compose --env-file deploy.env logs --tail 30
```

The Python server owns TUN/NAT inside its container and publishes UDP4433.
Keep keys and live configs private. Server restarts require matching session handling.

An optional HTTPS admin portal (status, config editing, restart) is described in [admin-portal.md](docs/admin-portal.md).

## Remaining gaps

Live HTTPS, QUIC, persistent connections, and Codex traffic have passed checks.
Combined-link speed gains and sustained game/call performance under real outages
still need validation. DNS/IPv6 coverage, a kill switch, full wire accounting,
and production fallback/native-server integration remain incomplete.
See [current status](docs/local-status.md).

## Development

```powershell
python -m unittest discover -s tests
go -C netstack test ./...
go -C native-edge test ./...
```

- [netstack/](netstack/): Windows userspace proxy.
- [native-edge/](native-edge/): experimental Go server.
- [tools/](tools/): builds, deployments, and diagnostics.

GameBond uses its own protocol and does not interoperate with Speedify.
