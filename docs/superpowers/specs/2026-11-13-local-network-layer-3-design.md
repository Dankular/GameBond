# Local Network Layer 3 Design

## Goal

Extend the Go client into an IPv4 router for configured local networks, with configurable DHCP service, DHCP relay, inter-network routing, and static routes. Keep the existing connected-device gateway working for existing configurations.

## Context

The existing `native-edge/lan.Gateway` owns one adapter and one fixed `TunnelIP`. It answers DHCP and ARP for that device, then sends eligible IPv4 packets to the tunnel. `lan.LeaseTable` persists those fixed-device leases. `lan.DeviceConfig` supports up to four `lan_devices` entries, and the Windows frame backend takes the selected adapter into Packet Filter tunnel mode. `native-edge/router` chooses between GameBond and OpenMPTCProuter by DSCP; it is not a local subnet route table. `native-edge/nat` implements outbound SNAT and is outside this design.

The existing router plan identifies a subnet behind a switch as planned work. This design generalizes that path while preserving the old single-device configuration and behavior.

## Scope and constraints

- Windows is the first supported runtime, following `docs/router-plan.md`.
- IPv4 only. IPv6 forwarding, dynamic routing protocols, WAN policy routing, DNAT, firewall policy, and NAT changes are excluded.
- Operate only on adapters explicitly assigned to local networks. Do not edit the Windows host routing table or take over ordinary host/uplink adapters implicitly.
- Preserve the current `lan_devices` JSON shape and its legacy behavior. New local-network configuration is opt-in.
- Model a local network as a named IPv4 prefix attached to a dedicated adapter and optional 802.1Q VLAN ID. The local router owns the configured gateway address on that network.
- A DHCP pool is optional per network. It includes start/end addresses, lease duration, DNS servers, and reservations. The gateway, network/broadcast addresses, static routes' next hops, and reservations are excluded from dynamic allocation.
- DHCP relay is optional per network and forwards client requests to explicitly configured IPv4 server addresses, preserving relay metadata and returning replies only to the originating local network/client. A network cannot run its own DHCP pool and relay at the same time.
- Static routes have a destination prefix, next-hop IPv4 address, and outgoing configured local network. Reject invalid, ambiguous, overlapping, recursive, or unreachable next hops at configuration load time. Connected routes take precedence over static routes; longest-prefix match selects among routes of the same class; equal-prefix duplicates are rejected.
- Inter-network forwarding is opt-in per network pair. The default is to block forwarding between local networks. Routed packets have TTL decremented, invalid sources/destinations are dropped, and the existing MTU/MSS handling is reused where applicable.
- VLAN-tagged frame support is conditional on a verified capability of the Windows Packet Filter backend. Untagged dedicated adapters and separate-adapter networks are the initial supported attachment modes. VLAN trunk mode must fail configuration clearly when the driver cannot deliver tagged frames intact.
- No switch management features are implied. DHCP snooping, STP, IGMP snooping, LACP, 802.1X, and Layer 2 ACLs remain out of scope.

## Architecture

Add a subnet-oriented routing core in `native-edge/lan`, separate from the existing one-device `Gateway`. It consumes normalized Ethernet/IPv4 frames from the existing frame-I/O abstraction, maintains a per-interface neighbor table, serves DHCP pools or relays requests, and forwards IPv4 packets using connected and static routes. Network configuration validation belongs in `native-edge/lan`; `appconfig` integrates it with strict top-level configuration validation.

The client runtime owns one local-router manager alongside the current `lanManager`. It opens only configured local-network adapters, dispatches ingress frames by adapter/VLAN, sends egress frames through the selected interface, and hands packets for the tunnel to the existing outbound path. The existing fixed-device manager remains the fallback for legacy `lan_devices` configurations. Configuration must reject adapter reuse across uplinks, legacy devices, and the new local networks.

The dashboard adds a Local Networks section for network interfaces, prefixes, gateway addresses, VLAN IDs, DHCP pool/reservations, relay server, inter-network forwarding policy, and static routes. It saves through the existing authenticated configuration APIs and presents validation errors returned by the daemon. Existing Connected devices UI remains available for legacy configurations.

## Configuration shape (proposed)

```json
{
  "local_networks": [
    {
      "name": "Office",
      "interface_id": "{ADAPTER-GUID}",
      "prefix": "192.168.40.1/24",
      "vlan_id": 40,
      "dhcp": {
        "pool_start": "192.168.40.100",
        "pool_end": "192.168.40.199",
        "lease_seconds": 86400,
        "dns": ["1.1.1.1", "8.8.8.8"],
        "reservations": [{"mac": "02:00:00:00:00:01", "ip": "192.168.40.10", "name": "printer"}]
      },
      "forward_to": ["Lab"]
    }
  ],
  "dhcp_relays": [],
  "static_routes": [
    {"destination": "10.50.0.0/16", "next_hop": "192.168.40.2", "interface": "Office"}
  ]
}
```

The exact JSON contract must be finalized during implementation planning. In particular, relay configuration should be represented as a mutually exclusive per-network mode rather than allowing both `dhcp` and relay settings on the same network.

## Runtime behavior

1. Load and validate the full local-network configuration before opening any adapter. Reject duplicate names, prefixes, VLAN IDs on the same trunk, conflicting addresses/pools/reservations, invalid interface identity, reused uplinks, and invalid route topology without partially starting the router.
2. Open each configured adapter and confirm its frame I/O is live. On startup failure, close all adapters opened for this local-router instance and report the affected network in status.
3. Parse Ethernet frames with optional 802.1Q headers, then dispatch by configured interface and VLAN. Unknown VLAN IDs and unsupported frame formats are dropped and counted.
4. Answer ARP for configured gateway addresses and learn neighbors only from valid frames on their attached network. Do not proxy ARP outside the configured routes.
5. Serve DHCP using a persistent lease table keyed by network and client identity. Support DISCOVER/OFFER, REQUEST/ACK, NAK, RELEASE, lease expiry, reservations, and standard gateway, subnet-mask, lease-time, and DNS options. Do not allocate a leased address to a second MAC.
6. For relay mode, forward BOOTP/DHCP requests with relay-agent address set to the local gateway address. Accept replies only from configured servers and only when transaction/client metadata matches a pending request; return the response on the originating interface/VLAN.
7. For IPv4 forwarding, validate source network, destination route, next-hop reachability, and forwarding policy. Apply longest-prefix match, decrement TTL, resolve the next-hop MAC using ARP, queue a bounded amount while resolution is pending, and drop with counters when resolution fails or the queue is full.
8. Preserve existing tunnel delivery for destinations in the GameBond tunnel subnet. Do not apply local-network routes to workstation-originated traffic.
9. Publish per-network state, DHCP pool/lease counts, relay status, route counts, neighbor state, and packet/drop counters in the client status document.

## Error handling and safety

- Invalid configuration is rejected before runtime changes; errors identify the field and conflicting network/route.
- Runtime adapter loss marks only that network down and retries through the established adapter-watch/retry pattern. Other networks and the tunnel continue operating.
- DHCP relay server timeouts do not trigger local DHCP fallback.
- All packet, neighbor, DHCP transaction, and pending-resolution queues have explicit size and lifetime bounds.
- Malformed, fragmented where unsupported, spoofed-source, TTL-expired, unroutable, unauthorized inter-network, and unsupported VLAN frames are dropped and counted.
- Dashboard saves are atomic and preserve unrelated configuration. A failed save leaves the active configuration and running interfaces unchanged.

## Acceptance criteria

1. Existing `lan_devices` configurations retain their current DHCP, lease persistence, ARP, forwarding, and status behavior.
2. A configured local network allocates addresses only from its validated pool, honors reservations, persists leases, and reports lease state.
3. A relay network forwards DHCP requests to configured servers and returns valid responses to the correct client on the correct interface/VLAN; unsolicited or mismatched replies are dropped.
4. Hosts on two configured local networks can communicate only when forwarding is enabled for that pair; TTL, source validation, route lookup, and neighbor resolution are enforced.
5. Static routes forward to reachable next hops using longest-prefix matching and reject invalid/unreachable routes before opening adapters.
6. Separate-adapter networks work on Windows with the existing Packet Filter frame path. VLAN mode is exposed only after a Windows driver capability check demonstrates correct tagged frame ingress/egress; otherwise the configuration is rejected with a clear error.
7. A dashboard operator can create/edit/remove networks, DHCP pools/reservations, relay settings, forwarding pairs, and static routes, and sees validation/runtime errors.
8. The feature remains IPv4-only and does not mutate the Windows host routing table or change SNAT/DNAT behavior.

## Verification strategy

- Unit tests for strict config validation, DHCP lease/pool allocation and persistence, DHCP relay transaction matching, VLAN frame parsing, connected/static route lookup, inter-network forwarding policy, TTL/source checks, ARP resolution, and bounded queue behavior.
- In-memory multi-interface integration tests for DHCP client-to-server and relay exchanges, inter-network packet forwarding, static route forwarding, adapter failures, and legacy `lan_devices` coexistence.
- Windows-target build plus a driver-backed capability probe for tagged frame ingress/egress before enabling VLAN trunk configuration. If physical hardware is unavailable, report VLAN support as unverified and leave it disabled by default.
- Dashboard endpoint and headless UI checks for configuration validation, persistence, and error display.
- No production adapter, Windows host route, or server config changes during verification.

## Delivery decomposition

1. Audit and prove the Windows frame-I/O capabilities, including tagged Ethernet behavior; finalize the configuration contract and adapter ownership rules.
2. Implement validated local-network configuration, per-network persistent DHCP pools, ARP/neighbor handling, and separate-adapter DHCP gateway runtime.
3. Implement route lookup and policy-controlled inter-network IPv4 forwarding, then static routes.
4. Implement DHCP relay with bounded transaction tracking and server validation.
5. Add dashboard configuration/status and documentation; only expose VLAN trunk controls if step 1 verifies driver support.

Each delivery stage must produce independently testable behavior, preserve legacy `lan_devices`, and update the feature inventory and router plan.
