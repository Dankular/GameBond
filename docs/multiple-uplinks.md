# Multiple uplinks

GameBond can bond 2 to 8 adapters on one Windows PC through one VPS session.
Each selected adapter gets its own socket, interface pinning, path health,
rate budget, link role, and usage accounting.

## Several Starlinks on one PC

1. Connect each independent Starlink uplink through a separate Windows network
   adapter. Several routers behind one ordinary switch/PC adapter do not become
   separate selectable paths.
2. Open **Select networks**, select 2 to 8 adapters, and save.
3. Use **Link roles & limits** to set each adapter's role and limits.
4. Reconnect the tunnel. Every selected link appears in the dashboard; offline
   links retain their identity and can return later.

Use [the three-link example](../configs/multi-link-client.example.json) for
manual configuration. Replace its addresses, gateways, indices, adapter GUIDs,
session, and peer with actual values. Existing two-link configs still work.

Adapters on overlapping LANs must have distinct stable Windows GUIDs and
interface indices so the userspace client can pin them independently. Config
validation covers this case; physical overlapping-subnet operation still needs
testing. Distinct LAN subnets avoid that ambiguity. The legacy Wintun route
backend continues to require distinct source addresses.

## Scope and verification

This is bonding through a shared VPS, not a distributed mesh between Starlinks.
Starlinks at separate locations would need remote gateway software, which this
change does not provide.

Three- and eight-path real UDP loopback tests cover bidirectional striping,
replica deduplication, and continuity when only one path remains. The Python
client also passes eight-path native Go interoperability with TCP repair and
primary/backup policies.

These checks prove software path handling, not combined satellite throughput.
Repeated physical multi-Starlink throughput and game/call outage tests remain.

After building the receiver probe, repeat native interoperability with:
```powershell
python tools/check_native_receiver.py --bonded --repair --policies --paths 8
```
