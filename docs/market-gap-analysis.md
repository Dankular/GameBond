# Market comparison, enterprise gaps, and the evidence to build them

Research date: 2026-11-11. Compares GameBond with commercial bonding and SD-WAN products,
lists what is missing for enterprise use, and ties each gap to the evidence already in this
repository (the Speedify 17.2.1.13911 static analysis, `findings.md`, the QoS reviews and the
router plan) so each item can be built from something concrete.

## Source quality

| Product | What was read | Confidence |
|---|---|---|
| Viprinet Gigabond Desktop 420 | Official datasheet, January 2026 | High |
| Viprinet Multichannel VPN Hub 1020 / 2020 / 2030 | Search-result excerpts only; the Hub 2020 PDF returned 404 | Low, indicative |
| Peplink SpeedFusion | Official SpeedFusion whitepaper, Balance datasheet (older revision), SpeedFusion/PepVPN brochure | High for features; throughput figures come from an older datasheet |
| Cradlepoint / Ericsson NetCloud | Vendor marketing page (Intelligent Bonding) | Medium, marketing |
| Speedify | Vendor competitor-comparison page | Low, competitor marketing |
| Fortinet, Mushroom Networks, Bondix, Teltonika, OpenMPTCProuter | No feature data retrieved | None |

Treat Speedify's statements about other vendors as unverified.

## What the competitors offer

**Viprinet.** Gigabond Desktop 420 bonds up to 4 lines (3 module slots plus a fixed 2.5G WAN),
up to 2,000 Mbps encrypted bonding, 2.5G LAN, Wi-Fi 6E, 20 W typical, 50 recommended users, SNMP
(basic, extended). Optional licences: Streaming Optimization (live video, PBX/VoIP trunking), Node
Stacking (merge several routers into one), Enterprise Node Features (VLANs, dynamic routing,
extended SNMP). Hubs (excerpts): 1U units of roughly 200 / 400 / 500 Mbit/s (1020 / 2020 / 2030),
optional hub redundancy, Hub Tunnel Segmentation (separate customers on one hub), SNMP, a paid
maintenance subscription.

**Peplink SpeedFusion.**
- Bonding with Dynamic Weighted Bonding (firmware 8.2.0+), Hot Failover with session persistence,
  WAN Smoothing (duplication; Normal 2x, Medium 3x, High 4x, Maximum), FEC (Low 13.3%, High 26.7%,
  Adaptive 6.7-20% overhead), smoothing and FEC together.
- Up to 13 links per bond (older datasheet); one tunnel per WAN-to-WAN pair (6 x 2 = 12 tunnels);
  80 bytes overhead per packet (IPsec: 58).
- Security: Diffie-Hellman exchange, 256-bit AES, keys derived from master keys and renegotiated at
  random intervals (perfect forward secrecy), separate keys per WAN-to-WAN link.
- Topologies point-to-point, star, mesh. Far end can be Peplink-hosted, a Peplink device, or a
  customer-hosted cloud VM (FusionHub). Default ports TCP 32015 and UDP 4500 (changeable).
- Several profiles per router (sub-tunnels) with their own WAN set, limits, smoothing and FEC.
  Outbound policy steers by protocol, port, application and client type; DPI recognises apps.
- Layer 2 VPN between sites (trunk or single VLAN). Traffic overflow: cheap links first, spill at
  capacity.
- DWB tuning: congestion latency level (Low/Default/High or a hard cut-off per WAN), ignore packet
  loss events (recommended for Starlink), disable bufferbloat handling, TCP ACK duplication on/off,
  packet jitter buffer (default 150 ms).
- Router: VLANs, L2TP/PPTP server, IPsec site-to-site, bandwidth usage monitor, VoIP QoS,
  user-group bandwidth control, high availability, Wi-Fi AP and captive portal, AP controller.
- InControl2: cloud controller with dashboard, group firmware policy and scheduling, bandwidth
  reports, remote configuration.
- Their LEO guidance: enable Ignore Packet Loss Event and FEC; test 5-10 minutes, not 20 seconds;
  keep link latencies similar; use low-latency links for the bond and high-latency ones as failover.

**Cradlepoint / Ericsson NetCloud (marketing).** Three combinable strategies: flow duplication,
flow balancing (percentage or dynamic), bandwidth aggregation. Application-aware routing, policies
set in NetCloud Manager and pushed to "10 locations or 1,000", cost tracking by location, gateway
cloud-delivered or customer-hosted. Their own view: bonding is not a silver bullet for Starlink.

**Speedify (competitor marketing).** Per-packet distribution; apps on five OSes and OpenWrt,
GL.iNet, Miri routers. Teams: dashboard, user provisioning, usage analytics, CSV, REST API.
Dedicated or self-hosted servers with static IP and port forwarding. Multi-dish Starlink status.

## Where GameBond stands

Already ahead of or level with the field on transport behaviour: per-packet bonding over up to 8
uplinks, parity FEC, adaptive duplication, loss steering, BFD (~300 ms), fast reroute with flow
pinning, CoDel with ECN, fair queueing, DSCP classes, adaptive reorder, per-path MTU discovery,
Starlink dish hints, a LAN-device gateway and an OMR split path. The gaps are mostly the
hub/fleet/security/management layer around the transport.

## Cross-reference: gap, evidence we hold, what is still unknown, how to build

Evidence names refer to this repository. "Static" means recovered from the Speedify binary's
decompiled output and is not original source or measured behaviour; do not copy opaque constants.

| Gap | Competitor reference | Evidence already in the repo | Unknown / caution | Build approach |
|---|---|---|---|---|
| **Key exchange, forward secrecy, rekey** | Peplink DH + random-interval renegotiation; per-link keys | Our code: ChaCha20-Poly1305 with a static 32-byte key (`bond/codec.go`), 3-way handshake in `bond/handshake.go` with no ephemeral exchange. Speedify static: uses BoringSSL TLS 1.3 and DTLS (`dtlssessionwrapper.cc`, `tls13_*.cc`, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") over gRPC, i.e. standard ECDHE-based sessions | No Speedify rekey literals found (search of quoted strings: zero matches) | Add X25519 ephemeral exchange authenticated by the PSK (Noise-style `XXpsk` or HKDF over the existing handshake), derive per-path keys, rekey on a timer and after a byte count. Go `crypto/ecdh` and `x/crypto/hkdf` are enough |
| **Multi-client hub** | Viprinet hub, FusionHub, Speedify servers | Our config pins one client (`client_tunnel_ip` 10.77.0.2, container entrypoint checks it). Speedify static: server allocates IPv4 and IPv6 tunnel addresses to the client ("Got bad ipv4/ipv6 allocation data from server"), a REST login (`/api/v1/users/login/`) and per-user auth | Allocation wire format not recovered | Session table keyed by client identity, address pool (`lan_tunnel_ips` already lists per-client addresses), per-client policy and counters, one TUN with a route per client |
| **Restricted-network transports** | Peplink TCP 32015; Speedify TCP/HTTPS/WebSocket | Speedify static: libwebsockets WebSocket upgrade, `h2 ws handshake`, HTTPS proxy auth retries, multiple transport kinds; our `carrier/` package already carries TLS (ALPN `gamebond/1`) and a relay | None blocking | Offer the bond over the existing carrier when UDP is blocked; keep UDP default |
| **Central management / fleet** | InControl2, NetCloud Manager, Viprinet VCM, Speedify Teams | `docs/admin-portal.md` (HTTPS portal, config edit, restart) and the status JSON; `docs/go-migration-ledger.md` lists remaining portal pieces | Fleet design is new work, not recoverable from Speedify (cloud service not in the binary) | Extend the admin portal to many servers/clients: config templates, health roll-up, staged rollout, REST API |
| **Identity, RBAC, audit** | SSO, roles, audit logs | `adminauth` package (password sessions); event journal (`eventjournal`) | Nothing recovered for SSO | Roles on the admin API, OIDC login, append-only audit log from the journal |
| **Observability export** | SNMP (Viprinet), syslog, usage reports | Status JSON, `appevents`, per-link counters; Speedify SDK exposes `bondingFiltered`/`poorConnection`/`slowConnection` (`channel-bonding-review.md`) | No SNMP/syslog strings in the binary | Prometheus endpoint from the status JSON, syslog sink, alert rules |
| **Hub high availability** | Viprinet hub redundancy, Peplink HA | None | Session takeover needs replicated key and sequence state | Warm standby with periodic state sync; clients fail to the second endpoint using the existing multi-path logic |
| **Tunnel profiles / sub-tunnels** | Peplink profiles with own links, limits, FEC | Static: Speedify per-DSCP queue policy, `analysis-scheduling.md` section 1 (weighted per-packet chooser, evidence `ev_ded286fc...`), our `QueuePolicy` per DSCP class | How classes map to link sets in Speedify is unresolved | Profile = link set + protection level + limits; class rules choose a profile. Reuse `Classifier` and `AdaptiveQoS` |
| **Configurable protection levels** | Peplink smoothing levels, FEC Low/High/Adaptive | Our thresholds are constants (`fecRatio`, `dupRatio`, `lossSteerRatio`). `analysis-recovery.md`: Speedify FEC unresolved (zero literals for fec/parity/erasure), so the FEC design is ours | Peplink figures (13.3% / 26.7% / 6.7-20%) are public targets only | Expose thresholds and parity group size as config presets; make group size adaptive (4 / 8 / 16) |
| **Delay-tolerant tuning (DWB knobs)** | Peplink cut-off latency, ignore loss events, jitter buffer, ACK duplication | `analysis-scheduling.md` section 5: separate health, capacity and usefulness states with hysteresis (static evidence `ev_d571ae77...`, `ev_a95ab895...`); our `bulkFiltered` margin, `updateReorderBudget` | Speedify thresholds not recovered | Per-path settings: hard latency cut-off, "loss is not congestion" flag for LEO, reorder budget cap, TCP ACK duplication switch |
| **End-to-end packet age** | n/a | `qos-review-0.3.4.md` item 3: carry one absolute deadline through queue, pacing and window waits; still open in our code | None | Stamp a deadline at admission, check at every wait, add post-dequeue expiry counters |
| **Persistent queue control details** | CoDel (Speedify static) | `qos-review-0.3.4.md` item 2 (static `ev_ce6883ba...`, interval/sqrt(count)); now implemented as `bond/codel.go` | Target/interval constants unrecovered; ours (12 ms / 120 ms) are unvalidated | Measure under load, tune per link type, expose in config |
| **Routed LANs, static routes, port forwards** | Peplink/Viprinet routing, Speedify static IP + port forwarding | `docs/router-plan.md` phases 3-6 (router config model, DNAT on the VPS, routing policy, subnet behind a switch) are written and still planned | The plan says DNS is done; DNS support has since been removed, so update that row | Implement phases 4 (DNAT/port forwards) and 6 (subnet) first; they unlock site-to-site |
| **IPv6** | Common | Speedify static: lwIP IPv6 (`ip6.c`, `nd6.c`, `icmp6.c`), server-allocated IPv6, packet header compression for IPv6 flows. Ours: IPv4 only | Header-compression format not recovered | Dual-stack TUN, IPv6 allocation in the handshake, NDP in the LAN gateway |
| **VLANs, L2 VPN** | Viprinet Enterprise Node, Peplink | `lan` package handles untagged Ethernet only | None | 802.1Q tags in `lan/frameio`, one gateway instance per VLAN |
| **Cross-platform clients** | Speedify (5 OSes) | Linux frame backend exists (`lan/frameio_linux.go`); the edge already builds for Linux; `remaining-tasks.md` | Windows capture (Packet Filter, ProxiFyre) has no Linux equivalent | Linux client using the TUN path used by the server edge |
| **Per-user / per-device bandwidth control** | Peplink user groups | Per-device counters in `lan`; per-link caps in `linkpolicy` | None | Token bucket per device in the gateway, driven by config |
| **Throughput proof** | Published per-model figures and a test method | `evidence/benchmark-go-edge-*.json`; `findings.md` "Validation needed before throughput claims" | No repeatable multi-link benchmark | Scripted 5-10 minute tests, both directions, 1 and N streams, per-path wire bytes, published results |
| **Zero-touch deployment, packaging** | Fleet provisioning | `tools/container-entrypoint.sh`, `dep.sh`-style scripts | None | Signed releases, config bootstrap token, auto-update channel |
| **Multi-dish Starlink view** | Speedify Starlink control center | `dishwatch` handles one dish | None | Dish list in config, per-uplink hints (the hint API is already per path) |

## Findings from cross-referencing

1. The Speedify binary supports the hub work with real evidence in three places: server-allocated
   addresses (multi-client pool), TLS 1.3/DTLS sessions (ephemeral keys), and WebSocket/HTTPS
   transports (restricted networks). It gives no help for fleet management, SNMP, SSO, VLANs or
   port forwarding, which must be designed from scratch or from Peplink's published behaviour.
2. Peplink's published numbers (smoothing 2x/3x/4x, FEC 13.3% / 26.7% / 6.7-20%, 150 ms jitter
   buffer, 8.2.0 DWB options) are the best targets for the protection-level presets, because the
   Speedify FEC design could not be recovered.
3. Two items the QoS reviews already listed are still open in our code: the shared end-to-end packet
   deadline and the separate health/capacity/usefulness path states.
4. One design tension to resolve: Peplink recommends ignoring loss as a congestion signal on
   Starlink and relying on FEC. GameBond already tries parity first (0.3-1.5%) and duplicates at
   1.5%, but still steers away at 4% smoothed loss and its budget can cut rate on loss. Make
   "loss is not congestion" a per-path option and compare with measurements.
5. `docs/router-plan.md` is stale about DNS (removed since) and should be updated when the routing
   phases are scheduled.

## Suggested order

1. Security: ephemeral key exchange with rekeying (small, self-contained, high value).
2. Multi-client server: session table, address pool, per-client policy and counters.
3. Protection presets and the DWB-style per-path settings, then the shared packet deadline.
4. Observability: Prometheus, syslog, alert rules.
5. Router phases 4 and 6 (DNAT, subnet), then IPv6 and VLANs.
6. Admin API with roles, audit log, then fleet management.
7. WebSocket/HTTPS fallback on the existing carrier.
8. Hub standby, Linux client, benchmark harness and published numbers.
