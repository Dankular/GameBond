# Local Network Layer 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in IPv4 local network DHCP service, DHCP relay, inter-network routing, and static routes to the Go client while preserving existing `lan_devices` behavior.

**Architecture:** Add a subnet-oriented local router to `native-edge/lan`, independent of the existing one-device `Gateway`. Validate the new configuration before opening interfaces, run it beside the legacy `lanManager`, and expose management and status through the existing Go dashboard. Use separate dedicated adapters first; permit VLAN-tagged network attachment only when the Windows Packet Filter path is proven to preserve tagged frames.

**Tech Stack:** Go, `net/netip`, existing raw Ethernet `lan.FrameIO`, Windows Packet Filter driver, strict JSON validation in `appconfig`, existing dashboard HTTP/config APIs and embedded JavaScript.

**Spec:** `docs/superpowers/specs/2026-11-13-local-network-layer-3-design.md`

## Global Constraints

- Windows is the first supported runtime.
- Forward IPv4 only; do not add IPv6, dynamic routing, WAN policy routing, DNAT, firewall policy, or NAT changes.
- Do not edit the Windows host routing table or implicitly take over host/uplink adapters.
- Preserve the current `lan_devices` JSON shape and runtime behavior; new configuration is opt-in.
- Configure local networks on explicitly assigned dedicated adapters; reject adapter reuse across uplinks, `lan_devices`, and local networks.
- Inter-network forwarding is blocked by default and enabled per network pair.
- DHCP pool and relay modes are mutually exclusive on each network.
- Bound packet, neighbor, DHCP transaction, and unresolved-next-hop queues by size and lifetime.
- Do not expose VLAN trunk configuration until Windows tagged-frame ingress and egress pass a driver-backed capability check.
- Do not modify production adapters, host routes, or server configuration during implementation verification.

## Review Focus

- DHCP pool overlap with the gateway, network/broadcast address, reservations, or static next hops must fail configuration validation.
- DHCP renewal, release, expiry, restart, and duplicate-MAC/address requests must not corrupt or duplicate leases.
- DHCP relay replies must match a pending transaction and configured server; late, unsolicited, or cross-interface replies must be dropped.
- Route lookup must choose longest prefix, prefer connected routes over static routes, reject recursion and unreachable next hops, and never fall through to the host routing table.
- Ingress spoofing, TTL expiry, unknown VLAN, queue exhaustion, adapter loss, and unauthorized inter-network traffic must fail closed without stopping unrelated networks or the tunnel.

---

### Task 1: Add and validate the local-network configuration contract

**Files:**
- Create: `native-edge/lan/local_config.go`
- Create: `native-edge/lan/local_config_test.go`
- Modify: `native-edge/appconfig/appconfig.go`
- Modify: `native-edge/appconfig/appconfig_test.go`
- Modify: `native-edge/appconfig/sections.go`
- Modify: `native-edge/cmd/client/main.go`

**Interfaces:**
- `lan.NetworkConfig`: `Name string`, `InterfaceID string`, `InterfaceIndex int`, `InterfaceName string`, `Prefix netip.Prefix`, `VLANID int`, `DHCP *lan.DHCPPoolConfig`, `Relay *lan.DHCPRelayConfig`, `ForwardTo []string`.
- `lan.DHCPPoolConfig`: `Start netip.Addr`, `End netip.Addr`, `LeaseSeconds int`, `DNS []netip.Addr`, `Reservations []lan.Reservation`.
- `lan.DHCPRelayConfig`: `Servers []netip.Addr`.
- `lan.StaticRoute`: `Destination netip.Prefix`, `NextHop netip.Addr`, `Interface string`.
- `lan.LocalConfig`: `Networks []lan.NetworkConfig`, `Routes []lan.StaticRoute`.
- `lan.LoadLocalConfig(networksRaw, routesRaw []byte, uplinkIDs, deviceAdapters []string, uplinkIndices, deviceIndices []int) (lan.LocalConfig, error)`: strict parser and cross-config adapter/route validation; legacy Linux device names use the `name:<interface>` token form; empty or omitted fields return an empty config.
- Runtime top-level JSON keys: `local_networks` and `static_routes`. DHCP relay is mutually exclusive with a `dhcp` pool on a `local_networks` entry; either can be omitted for statically addressed hosts. Network entry keys are `name`, `interface_id` (Windows), `interface_name` (Linux), `interface_index`, `prefix`, optional `vlan_id`, optional `dhcp`, optional `relay`, and `forward_to`. DHCP keys are `pool_start`, `pool_end`, optional `lease_seconds`, optional `dns`, and optional `reservations` with `mac`, `ip`, and `name`.

- [ ] **Step 1: Add failing parser tests** for missing/valid single network, malformed fields, invalid prefix/gateway, invalid pool, reservations outside pool/subnet, invalid DNS, invalid relay server, both/neither DHCP and relay modes, duplicate names/prefixes/VLAN IDs, route recursion/unreachable next hop, adapter reuse, and legacy `lan_devices` coexistence.
- [ ] **Step 2: Run the focused tests** with `go test ./lan -run 'TestLoadLocalConfig'` and `go test ./appconfig -run 'Test.*LocalNetwork'`; confirm the new cases fail before implementation.
- [ ] **Step 3: Implement typed configuration parsing and validation** in `lan/local_config.go`. Require valid IPv4 unicast subnet/gateway, a contiguous prefix, a unique name, valid dedicated interface identity, at most one DHCP/relay mode, bounded DHCP settings and reservation uniqueness, valid VLAN range 1–4094, and reachable nonrecursive static next hops. Reject route destinations that overlap a connected network and duplicate destination prefixes.
- [ ] **Step 4: Integrate strict top-level validation** in `appconfig` and the client config decode in `cmd/client/main.go`. Feed current uplink and legacy LAN adapter identities into `LoadLocalConfig` before any frame-I/O adapter opens.
- [ ] **Step 5: Run the focused config tests** and confirm legacy appconfig vectors/configs still validate unchanged.
- [ ] **Step 6: Commit** as `feat: validate local network routing config`.

### Task 2: Implement network-scoped DHCP pools and lease persistence

**Files:**
- Create: `native-edge/lan/pool.go`
- Create: `native-edge/lan/pool_test.go`
- Modify: `native-edge/lan/gateway.go` only to share existing bounded DHCP parsing/build helpers where safe
- Modify: `native-edge/cmd/client/lanleg_test.go` only if adding a legacy coexistence regression

**Interfaces:**
- `lan.Reservation`: `MAC [6]byte`, `IP netip.Addr`, `Name string`.
- `lan.PoolLease`: `Network string`, `IP netip.Addr`, `MAC [6]byte`, `Hostname string`, `Granted time.Time`, `Expires time.Time`, `Reserved bool`.
- `lan.OpenPoolLeaseTable(path string) *lan.PoolLeaseTable`, `(*PoolLeaseTable).GetByMAC(network string, mac [6]byte) (lan.PoolLease, bool)`, `(*PoolLeaseTable).GetByIP(network string, ip netip.Addr) (lan.PoolLease, bool)`, `(*PoolLeaseTable).Put(lease lan.PoolLease)`, `(*PoolLeaseTable).Release(network string, mac [6]byte)`, `(*PoolLeaseTable).Expire(now time.Time)`.
- `lan.NewDHCPServer(network lan.NetworkConfig, leases *lan.PoolLeaseTable, now func() time.Time) (*lan.DHCPServer, error)`.
- `(*lan.DHCPServer).Handle(frame []byte) (reply []byte, handled bool)` handles DHCP DISCOVER, REQUEST, RELEASE; returns Ethernet reply frames; malformed/non-DHCP input is unhandled or dropped without panic.

- [ ] **Step 1: Add failing tests** for deterministic pool allocation, lease reuse by MAC, reservation precedence, DISCOVER/OFFER, REQUEST/ACK, invalid/out-of-pool REQUEST/NAK, RELEASE, lease expiry, hostname option, gateway/mask/lease/DNS DHCP options, malformed packets, duplicate requests, and restart persistence.
- [ ] **Step 2: Run** `go test ./lan -run 'TestDHCPServer|TestPoolLease'`; verify new cases fail.
- [ ] **Step 3: Implement network-keyed lease persistence** using atomic temp-file replacement and private runtime file permissions. Preserve existing `LeaseTable` file schema and behavior for fixed `lan_devices` leases.
- [ ] **Step 4: Implement the DHCP pool server** using bounded packet parsing and per-network allocation. Use reservations first; otherwise choose the lowest free address in the configured range. Persist only valid ACK/release/expiry changes. Never allocate an address held by another MAC.
- [ ] **Step 5: Run** `go test ./lan -run 'TestDHCPServer|TestPoolLease|TestNewGateway|TestGateway'` and confirm both new and legacy paths pass.
- [ ] **Step 6: Commit** as `feat: serve DHCP pools on local networks`.

### Task 3: Implement Ethernet/VLAN parsing, ARP neighbors, and local route forwarding

**Files:**
- Create: `native-edge/lan/local_router.go`
- Create: `native-edge/lan/local_router_test.go`
- Create: `native-edge/lan/routes.go`
- Create: `native-edge/lan/routes_test.go`
- Modify: `native-edge/lan/packet.go`

**Interfaces:**
- `lan.FramePort`: `Network lan.NetworkConfig`, `IO lan.FrameIO`.
- `lan.NewLocalRouter(config lan.LocalConfig, ports []lan.FramePort, outbound func([]byte) bool, now func() time.Time) (*lan.LocalRouter, error)`.
- `(*lan.LocalRouter).HandleFrame(interfaceID string, frame []byte)` handles DHCP/ARP/IP ingress.
- `(*lan.LocalRouter).ForwardFromTunnel(packet []byte) bool` routes a tunnel packet to a configured local destination and reports whether a configured local route owned it.
- `(*lan.LocalRouter).Routes() []lan.RouteStatus`, `(*lan.LocalRouter).Stats() lan.LocalRouterStats` provide stable status snapshots.
- Internal `RouteTable.Lookup(dst netip.Addr) (lan.ResolvedRoute, bool)` applies connected-route precedence, then longest-prefix static route.

- [ ] **Step 1: Add failing tests** for untagged and 802.1Q parse/build, unknown VLAN rejection, ARP gateway replies, neighbor learning on the correct network, connected-route selection, static longest-prefix selection, connected-route precedence, inter-network forward allow/deny, TTL decrement/expiry, source-prefix enforcement, no host-route fallback, TCP MSS/MTU behavior, and bounded unresolved-neighbor queue expiry.
- [ ] **Step 2: Run** `go test ./lan -run 'Test.*(LocalRouter|RouteTable|VLAN|Neighbor)'`; confirm new cases fail.
- [ ] **Step 3: Implement Ethernet and optional VLAN frame helpers** with bounds checks. Keep VLAN handling behind `LocalRouter` configuration; expose no runtime enablement until Task 6 driver probe passes.
- [ ] **Step 4: Implement a bounded per-network ARP neighbor cache** and gateway ARP responder. Learn only valid senders on their ingress network; use a bounded pending packet queue while resolving next hops and expire queued packets on timeout.
- [ ] **Step 5: Implement route table construction and lookup** from connected prefixes plus static routes; reject ambiguous destinations and recursive next hops. Add per-network-pair allow-list with deny-by-default forwarding.
- [ ] **Step 6: Implement forwarding** with ingress source validation, route ownership, destination neighbor selection, TTL decrement, MTU/MSS handling, per-egress frame writes, tunnel callback for tunnel-owned destinations, and counters for every drop class. Ensure packets addressed to configured local prefixes never fall through to workstation networking.
- [ ] **Step 7: Run** the focused LAN tests and all existing `lan` package tests; confirm fixed-device gateway behavior remains unchanged.
- [ ] **Step 8: Commit** as `feat: route packets between configured local networks`.

### Task 4: Implement DHCP relay with transaction validation

**Files:**
- Create: `native-edge/lan/relay.go`
- Create: `native-edge/lan/relay_test.go`
- Modify: `native-edge/lan/local_router.go`

**Interfaces:**
- `lan.NewDHCPRelay(network lan.NetworkConfig, now func() time.Time) (*lan.DHCPRelay, error)`.
- `(*lan.DHCPRelay).HandleClient(frame []byte) (serverPackets [][]byte, handled bool)` validates a DHCP client frame, sets relay address and records a bounded transaction.
- `(*lan.DHCPRelay).HandleServer(server netip.Addr, packet []byte) (clientFrame []byte, handled bool)` validates configured server, transaction ID, client hardware address, relay address, and lifetime before producing a client-side frame.
- Relay transactions expire after a fixed bounded timeout; one transaction key is `(xid, chaddr, ingress-network)` and duplicate client retransmissions refresh only that matching entry.

- [ ] **Step 1: Add failing tests** for DISCOVER and REQUEST relay forwarding, relay address insertion, server response forwarding, wrong server, unknown XID, mismatched MAC/relay address, timeout, duplicate/retransmitted request, oversized transaction table, malformed packets, and isolation across interfaces/VLAN IDs.
- [ ] **Step 2: Run** `go test ./lan -run 'TestDHCPRelay'`; confirm new tests fail.
- [ ] **Step 3: Implement bounded relay transaction tracking** with injected clock, configured-server allow-list, and validated response mapping. Relay timeout must not start or fall back to a local DHCP pool.
- [ ] **Step 4: Connect relay requests and responses to the local router** with explicit server UDP I/O that binds to a configured local-network path and cannot become an arbitrary host-network forwarder. Keep all sockets/context resources closed on manager shutdown.
- [ ] **Step 5: Run** `go test ./lan -run 'TestDHCPRelay|TestLocalRouter'` and confirm DHCP server mode and relay mode remain mutually exclusive.
- [ ] **Step 6: Commit** as `feat: relay DHCP for local networks`.

### Task 5: Integrate runtime lifecycle and status without changing legacy LAN behavior

**Files:**
- Create: `native-edge/cmd/client/localnet.go`
- Create: `native-edge/cmd/client/localnet_test.go`
- Modify: `native-edge/cmd/client/main.go`
- Modify: `native-edge/cmd/client/lanopen_windows.go`
- Modify: `native-edge/cmd/client/lanopen_linux.go`
- Modify: `native-edge/cmd/client/lanleg.go` only for explicit adapter ownership coordination

**Interfaces:**
- `localNetworkManager` owns the parsed `lan.LocalConfig`, open ports, lease table, `lan.LocalRouter`, relay UDP resources, retries, and status.
- `newLocalNetworkManager(rawNetworks, rawRoutes json.RawMessage, uplinkIDs, deviceIDs []string, uplinkIndices, deviceIndices []int, mtu int) (*localNetworkManager, error)` validates before opening frame I/O.
- `(*localNetworkManager).start(ctx context.Context)`, `(*localNetworkManager).close()`, `(*localNetworkManager).dispatchTunnel(packet []byte) bool`, `(*localNetworkManager).status() any`.
- Frame callbacks include the configured interface identity so ingress networks cannot be inferred from spoofable packet fields.

- [ ] **Step 1: Add manager tests** with fake `FrameIO` for validation-before-open, multi-adapter lifecycle, DHCP pool response, route forwarding, relay start/stop, adapter loss/retry, one adapter failing while another remains active, status counters, and conflicts with uplinks/legacy devices.
- [ ] **Step 2: Run** `go test ./cmd/client -run 'TestLocalNetworkManager'`; confirm new cases fail.
- [ ] **Step 3: Implement manager startup and cleanup**. Open all local network frame ports only after complete validation; close partial opens on failure. Use existing five-second LAN retry conventions without restarting tunnel or unrelated networks.
- [ ] **Step 4: Wire the manager into `main.go`** alongside `lanManager`. Existing tunnel delivery tries local network destinations before the generic stack; legacy `lanManager` keeps its existing dispatch path. Outbound local packets use the established `bridge.Send` callback.
- [ ] **Step 5: Add status fields** for network identity/up/error, prefix/VLAN mode, DHCP pool/free/leased counts, relay state, route and neighbor counts, bytes/packets, and drops. Ensure status construction remains safe when no local networks are configured.
- [ ] **Step 6: Run** existing focused LAN/client lifecycle tests and verify no behavior change with absent `local_networks`/`static_routes` and with legacy `lan_devices` only.
- [ ] **Step 7: Commit** as `feat: run local network router in client`.

### Task 6: Probe VLAN capability and expose only verified attachment modes

**Files:**
- Create: `native-edge/pktfilter/vlan_probe_windows.go`
- Create: `native-edge/pktfilter/vlan_probe_windows_test.go`
- Modify: `native-edge/pktfilter/driver_windows.go`
- Modify: `native-edge/lan/local_config.go`
- Modify: `native-edge/cmd/client/localnet.go`

**Interfaces:**
- `pktfilter.ProbeVLANFrames(adapterID string) (pktfilter.VLANCapability, error)` returns ingress/egress capability and a diagnostic reason; unsupported, inconclusive, or unverified results disable trunk mode.
- `lan.LocalConfig` validation accepts a nonzero VLAN ID only when runtime capability is verified for that adapter; config-only validation may parse VLAN IDs but runtime startup reports and rejects unsupported trunk configuration before other networks start.

- [ ] **Step 1: Add probe tests** for untagged pass-through, 802.1Q ingress preservation, tagged egress preservation, unsupported driver response, adapter disappearance, and inconclusive probe. Use a fake driver for deterministic cases.
- [ ] **Step 2: Run Windows-target focused pktfilter tests** and confirm the probe cases fail before implementation.
- [ ] **Step 3: Implement the capability query** using only the existing driver/frame interface. Do not send VLAN test traffic onto a production/user adapter; require an isolated loopback/test adapter or report capability unverified.
- [ ] **Step 4: Gate VLAN network startup** on verified ingress and egress capability. Separate-adapter, untagged local networks remain available if VLAN capability is unsupported.
- [ ] **Step 5: Run the Windows-target build and probe tests**; record if physical driver validation is unavailable. Do not enable VLAN by default based only on a fake driver test.
- [ ] **Step 6: Commit** as `feat: gate local VLANs on driver capability`.

### Task 7: Add dashboard configuration and operator documentation

**Files:**
- Create: `native-edge/dashboard/local_networks.go`
- Create: `native-edge/dashboard/local_networks_test.go`
- Modify: `native-edge/dashboard/dashboard.go`
- Modify: `native-edge/dashboard/widget.html`
- Modify: `native-edge/dashboard/widget_setup.js`
- Modify: `native-edge/dashboard/widget_settings.js`
- Modify: `FEATURES.md`
- Modify: `docs/router-plan.md`
- Modify: `docs/lan-devices.md`

**Interfaces:**
- `GET /api/local-networks` returns adapter inventory, saved `local_networks`, `static_routes`, and live local-network status.
- `PUT /api/local-networks` accepts exactly `{ "local_networks": [...], "static_routes": [...] }`, validates the complete document using the same `lan.LoadLocalConfig` path, atomically saves both keys together, and returns the daemon validation message on failure.
- The dashboard Local Networks form edits networks, DHCP pools/reservations, relay mode/server list, inter-network `forward_to`, static routes, and shows per-network runtime status. VLAN controls are hidden/disabled unless runtime reports the adapter capability as verified.

- [ ] **Step 1: Add failing endpoint tests** for GET data, valid atomic save, invalid subnet/pool/route, duplicate adapter ownership, unknown keys, partial request rejection, corrupt existing config preservation, and relay/pool exclusivity.
- [ ] **Step 2: Add headless UI checks** for network add/edit/remove, DHCP pool/reservation fields, relay toggle, forwarding pair selection, static route editing, save errors, reconnect messaging, responsive layout, and VLAN gating.
- [ ] **Step 3: Run focused dashboard endpoint/UI checks** and confirm they fail before implementation.
- [ ] **Step 4: Implement authenticated GET/PUT endpoints** using existing `configSectionWithConfig`/atomic config save patterns; save both keys together and preserve all unrelated settings.
- [ ] **Step 5: Implement the Local Networks view** with field-level validation, daemon error display, clear DHCP-versus-relay selection, default-deny forwarding copy, and status display. Preserve the existing Connected devices editor and setup flow.
- [ ] **Step 6: Update `FEATURES.md`, `docs/router-plan.md`, and `docs/lan-devices.md`** to distinguish verified existing per-device DHCP from new pool/relay/inter-network routing support and record platform/driver verification limits.
- [ ] **Step 7: Run focused dashboard checks** and inspect the rendered Local Networks view at desktop and narrow widths.
- [ ] **Step 8: Commit** as `feat: manage local layer 3 networks in dashboard`.

### Task 8: End-to-end regression and release readiness

**Files:**
- Create: `native-edge/lan/local_e2e_test.go`
- Modify: `native-edge/appconfig/appconfig_test.go` if cross-feature regression coverage is needed
- Modify: `FEATURES.md` and `docs/router-plan.md` for final evidence only

- [ ] **Step 1: Add in-memory end-to-end tests** for a DHCP client on network A, routed packet from A to B, static next hop, DHCP relay round-trip, tunnel-bound destination dispatch, route rejection, TTL expiry, and coexistence with one legacy `lan_devices` gateway.
- [ ] **Step 2: Run focused LAN, appconfig, dashboard, and client tests**; address regressions in the owning task before proceeding.
- [ ] **Step 3: Run full native-edge tests and Windows-target builds** with `GOFLAGS=-buildvcs=false`; collect command output and keep any environment/hardware limits explicit.
- [ ] **Step 4: Verify configuration behavior** for no local network keys, local networks only, legacy devices only, mixed legacy/new interfaces, DHCP relay, static routes, and unsupported VLAN IDs.
- [ ] **Step 5: Update feature docs with evidence**. Mark VLAN trunk support as unsupported/unverified unless the driver-backed capability check was completed with isolated hardware.
- [ ] **Step 6: Commit** as `test: verify local layer 3 routing flows`.

## Plan self-review

- Spec coverage: config validation (Task 1), pool DHCP/leases (Task 2), VLAN frames/ARP/routing/inter-network policy/static routes (Task 3), relay (Task 4), runtime lifecycle/status (Task 5), driver-gated VLAN (Task 6), dashboard/docs (Task 7), end-to-end/compatibility (Task 8).
- Placeholder scan: no TBD/TODO implementation steps; hardware-dependent VLAN evidence has an explicit unsupported outcome.
- Interface consistency: `NetworkConfig`, `LocalConfig`, `StaticRoute`, and DHCP types originate in Task 1; `PoolLeaseTable`/`DHCPServer` in Task 2; `LocalRouter` in Task 3; `DHCPRelay` in Task 4; runtime manager in Task 5; dashboard consumes Task 1 parser and Task 5 status.
- Review focus mapped: DHCP allocation/lease conflicts (Task 2), relay transaction isolation (Task 4), route lookup and no host fallback (Task 3), spoofing/TTL/queues/adapter failures (Tasks 3 and 5), VLAN failure-closed gating (Task 6).
