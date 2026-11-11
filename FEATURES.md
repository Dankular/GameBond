# GameBond features

What the transport and the desktop client do, and the config flag that controls each
one. "Default" is the value when the flag is absent. Counters appear under
`transport` in the status JSON and in the widget's Issues tab.

## Bonding

| Feature | What it does | Flag (default) |
|---|---|---|
| Bonding | Sends bulk traffic across up to 8 IPv4 uplinks in proportion to each path's measured capacity | `bonding_mode` |
| Per-path congestion budget | Each uplink has its own rate, window and loss accounting; a congested path stops taking bulk | always on |
| Delay control | Cuts a path's rate when a standing queue builds | `delay_control` (off) |
| Link roles and policies | Primary, backup, never; speed limits and usage caps per uplink | `link_policies` |
| Path MTU discovery | Probes each path for the largest frame that fits | `path_mtu_discovery` (off) |
| Gameplay redundancy | Priority classes (DSCP 46 and others) are duplicated on every ready path | `adaptive_qos`, queue policies |

## Reliability and loss recovery

| Feature | What it does | Flag (default) |
|---|---|---|
| Reorder buffer | Per-flow in-order delivery with a deadline; late packets are still delivered | always on |
| Adaptive reorder wait | Widens the TCP wait up to 1.6x while packets keep arriving after it, relaxes when they stop; UDP keeps a short wait | always on (`ReorderScale`) |
| TCP repair | The receiver requests missing TCP packets; the sender resends from its cache | `loss_tracking` (off) |
| Parity FEC | For 0.3-1.5% loss, one XOR parity frame per 8 packets lets the receiver rebuild one missing packet per group | automatic |
| Protection presets | Move the loss levels at which parity and duplication start: `off`, `low` (parity 0.5%, duplicate 3%), `normal` (0.3% / 1.5%), `high` (0.1% / 0.5%), `max` (always duplicate bulk while two paths are ready) | `protection` (`normal`) |
| Adaptive duplication | At 1.5% loss or more (or a Starlink dish "degraded" hint) bulk is also sent on a second path; first copy wins | automatic |
| Loss steering | Bulk leaves a path whose smoothed loss reaches 4% and returns below 2% after at least 3 s | automatic |
| Lost vs late | Issues tab separates packets that never arrived from ones that arrived after the wait | always on |

## Fast failover

| Feature | What it does | Flag (default) |
|---|---|---|
| BFD | A 100 ms frame exchange per path; a path is Up only while both ends hear each other (500 ms detection: 5 missed 100 ms intervals; one-way failures included; per-path state, flap counts and last cause appear in the status under `transport.paths[].bfd`), with a 2 s hold-down after a failure | always on; older peers fall back to the silence timer |
| Suspect-path replay | Bulk avoids a suspect path and its recent packets are replayed on a live path | `failover_replay` (off) |
| Flow pinning (ECMP) | Each bulk flow sticks to one path so it arrives in order; new flows pin to the least loaded path; a flow spills to others only when its pin is busy more than 20 ms | `flow_pinning` (off) |
| Fast reroute | Each pinned flow has a precomputed backup and flips to it on the next packet when BFD, suspect state, loss steering or a hint takes the pin out | with `flow_pinning` |

## Queueing and QoS

| Feature | What it does | Flag (default) |
|---|---|---|
| Fair queue | Per-flow deficit round robin on the bulk queue so one download cannot starve a sparse flow | always on |
| CoDel with ECN | A flow whose packets wait over 12 ms for 120 ms is ECN-marked (CE) if it negotiated ECN, otherwise dropped | `codel` (off) |
| DSCP classes | DSCP selects the queue, expiry age and whether a class is replicated; game UDP ports are marked DSCP 46 | `queue_policies`, `game_udp_ports` |
| Flow profiles | Application traffic profiles retag flows | `flow_profiles` |

## Desktop client

- All-app or selected-app capture through ProxiFyre and the Windows Packet Filter driver.
- Widget and tray: connection health, per-link graphs, app traffic, Issues tab, settings.
- Connected devices: a PS5, laptop or phone on a spare adapter or an access point gets its own tunnel address, with a per-device round-trip probe ([setup](docs/lan-devices.md)).
- Starlink dish telemetry as a degraded-path hint.
- Optional HTTPS admin portal on the server ([admin-portal.md](docs/admin-portal.md)).

## Where the code lives

`native-edge/bond/`: `sender.go`, `receiver.go`, `reorder.go`, `repair.go`,
`fec.go` and `fec_send.go`, `bfd.go`, `pin.go`, `failover.go`, `codel.go`,
`fairqueue.go`, `transmit_queue.go`, `qos.go`. Frame kinds are in `codec.go`
(Parity = 18, BFD = 19). New kinds are ignored by older peers, so a mixed
old/new pair keeps working with the new features inactive.

## Gateway, firewall and router functions

GameBond is a tunnel with a small gateway and NAT, not a general router or a host
firewall. This is everything it does in those roles.

### LAN-device gateway (client, `native-edge/lan`)

One gateway per attached device (PS5, laptop, phone, access point) on its own adapter:
- Answers ARP for the gateway address and sends unicast ARP probes to time the adapter-to-device leg.
- DHCP server for the device: offer, ack and nak, 24 h lease, handing out its fixed tunnel address (10.77.0.x).
- Persistent DHCP lease table (`.runtime/lan-leases.json`): name, address, MAC, lease state and expiry per device, saved on every ACK, release and MAC change. After a client restart each device is restored as leased, its remembered MAC is ARP-probed immediately, and the gateway announces itself with a gratuitous ARP, so a device with a valid lease is adopted again without a DHCP exchange or an `ipconfig /renew`. A remembered MAC is only a hint: any other device can still claim the address until the holder is heard from. DHCPRELEASE is honoured, expired leases are not restored, and a corrupt table starts empty.
- Forwards the device's IPv4 into the tunnel and delivers tunnel packets back to it.
- Device MAC is learned from the first frame or pinned with `device_mac`. Frames from any other MAC are dropped (`ForeignMACDropped`).
- Source-address check: packets whose source is not the device's leased address are dropped (`SpoofedSourceDropped`).
- Drops local-only and wrong-destination traffic (`LocalOnlyDropped`, `WrongDestination`) and malformed frames.
- TTL handling (`TTLExpired`), fragmentation to the tunnel MTU (1280) when a packet is too large and DF is clear, and ICMP "fragmentation needed" when DF is set (`FragNeededSent`).
- Presence tracking: present, leased, silent-for, per-device byte and packet counters.

### NAT and forwarding (server)

- IP forwarding on in the container; `gamebond0` TUN at 10.77.0.1.
- Source NAT: an nftables `masquerade` rule for the tunnel subnets out of the WAN interface.
- Fragment handling: an nftables prerouting rule clears the DF bit on oversized UDP arriving from the WAN so it can be fragmented instead of lost.
- Userspace NAT (`native-edge/nat`): stateful, port-restricted cone source NAT for TCP, UDP and ICMP echo (plus ICMP errors quoting a known mapping). Fragments, other ICMP types and other protocols are dropped and counted. Used by the OMR router path.
- The container entrypoint refuses to start if the config is not the expected server layout, if forwarding is off, or if a `gamebond` nft table already exists.

### Access control (what acts like a firewall)

- Authenticated, encrypted transport: frames carry a session prefix and are checked against the session key and sender identity. Unknown peers, bad prefixes and frames below the replay floor are rejected (`HandshakeRejected`, `FloorDrops`), and a replay window drops duplicates.
- Per-path link policy: a path set to `never`, or past its usage cap with `overlimit: stop`, is blocked from carrying data (`PolicyDrops`).
- Application authorization (client): captured applications are matched against a policy file by normalised executable path; each rule picks a traffic profile (automatic, gaming, streaming, call, bulk) or denies. Flows from other applications are not routed into the tunnel. This governs what enters the tunnel; it is not a host firewall.
- Capture integrity: the process-attribution extension is hash-checked before ProxiFyre is staged.
- Admin portal: HTTPS with authentication for status, config edits and restart.

### Router functions

- Multi-uplink routing on the client: each uplink gets its own lowest-cost default gateway; adapters are watched for changes.
- Traffic-class routing (`native-edge/router`): gameplay (DSCP 46) and calls (DSCP 26) go over GameBond; everything else can go through an OpenMPTCProuter tunnel behind a source NAT. A flow stays on one transport and is re-decided if that transport stops being ready.
- Per-flow path choice inside the bond: capacity-weighted striping, flow pinning with fast reroute, loss steering, duplication (see above).
- Link roles (primary, backup, never) and per-link speed and usage limits.

### Not provided

No port forwarding, inbound firewall rules, DNS server or resolver, UPnP, VLANs, or IPv6 forwarding. DNS settings were removed from the widget.
