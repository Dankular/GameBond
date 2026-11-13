# Linux Router Capabilities Design

## Goal

Extend GameBond's Linux gateway into a managed router that delivers the requested HA,
link aggregation, routing, WAN policy, security, LAN services, QoS, and operational
reporting capabilities. Configuration and status must be managed coherently through
GameBond, while mature Linux services and kernel facilities implement protocol-heavy
functions where that reduces risk.

The repeated requests for Internet Quality and Outage Reporting and Policy-based WAN
and VPN Routing are each one capability. The existing local-network Layer 3 design is
related work and remains a separate, narrower design; its platform assumptions must be
reconciled before implementation overlaps its configuration or runtime.

## Context and assumptions

- The target is a Linux GameBond gateway, as selected in the conversation. This is a new
  gateway deployment target, not an expansion of the Windows desktop client.
- The existing edge server is containerized and coexists with OpenMPTCProuter. Host
  networking features that need interfaces, kernel routing, or multicast must run in a
  clearly defined host or privileged gateway boundary; the existing unprivileged server
  container must not silently take ownership of host networking.
- GameBond provides one validated configuration model, an authenticated management
  surface, status, events, and safe apply/rollback. Linux kernel facilities and
  established services provide protocol implementations where appropriate.
- IPv4 is the initial scope unless an existing capability already requires dual stack.
  IPv6 behavior is not implied by this request and must be designed separately.
- A deployment can enable only features supported by its interfaces, kernel, packages,
  and topology. Unsupported configurations fail validation before they alter live state.

## Capability scope

### WAN and routing

- Policy-based routing across WAN links and VPN transports, including ordered rules,
  health-aware failover, and explicit behavior when the selected path is unavailable.
- Dynamic routing with OSPF and BGP, with explicit neighbor, prefix, and route-policy
  controls. Imported routes must be bounded by configured policy before entering the
  forwarding table.
- UniFi LTE Backup as an additional failover uplink using the existing uplink abstraction
  where compatible; discovery, modem status, and reconnect behavior need a platform probe.
- Internet quality and outage reporting with per-WAN probe health, latency, loss,
  transition events, and bounded historical retention.

### Availability and link capacity

- VRRP active/standby gateway redundancy. The standby monitors health and assumes the
  virtual address only after the configured failure condition. Configuration includes
  priority, preemption policy, advertisement timing, and tracked interfaces/services.
  Session continuity through replicated connection state is not promised unless a later
  design proves and implements it.
- LACP link aggregation with membership and operational state surfaced in status. Member
  interfaces must be dedicated to the aggregate and rejected if already assigned to WAN,
  LAN, or another managed feature.

### Forwarding, services, and security

- Advanced NAT: SNAT, DNAT, masquerade, NAT pools, and 1-to-1 mappings, with conflict
  detection and inspectable counters.
- Customizable DHCP service: per-network pools, reservations, lease options, and bounded
  persistent leases.
- mDNS forwarding/reflecting between explicitly selected networks, with scope controls.
- IGMP proxy between configured downstream and upstream interfaces, with membership and
  forwarding state visible.
- Integrated RADIUS authentication and accounting service, plus RadSec TLS transport for
  configured RADIUS peers. The integrated service and RadSec client/server roles must be
  explicit in the final contract; credentials and private keys are never returned by the
  management API.
- Virtual Network Override: an administrator may explicitly assign an eligible device
  or traffic identity to a selected virtual network, subject to authorization and
  network isolation policy.

### Traffic management and visibility

- Advanced QoS with classification, per-class and per-network rates/priorities, and
  queueing controls. Existing GameBond adaptive QoS remains available and the mapping
  between its classes and Linux traffic control must be explicit.
- All Traffic Flows reporting with source/destination, protocol, ports where available,
  selected policy/path, byte and packet counters, and timestamps. Retention, access
  control, and redaction are configurable.
- MAC address table sizing: configure and report the maximum learned entries for each
  managed Layer 2 network, with deterministic behavior and counters when the limit is
  reached. This interpretation should be confirmed during planning against the intended
  hardware/bridge model.

## Approaches considered

1. Reimplement every protocol in GameBond. Rejected because it duplicates mature routing,
   redundancy, and authentication implementations and expands protocol risk.
2. Use a GameBond Linux control plane with kernel networking and established Linux
   services behind narrow adapters. Recommended: one configuration and status model,
   while protocol state remains owned by the correct system component.
3. Require an external general-purpose router stack and have GameBond only display it.
   Rejected because it does not provide a coherent GameBond-managed capability surface.

## Architecture

1. **Gateway control plane:** a Linux service owns the validated desired configuration,
   capability detection, apply orchestration, status snapshots, audit events, and
   rollback. It uses narrow adapters for network links, routes/rules, firewall/NAT,
   traffic control, and service configuration. No arbitrary shell strings are accepted
   from configuration or the API.
2. **Protocol providers:** mature Linux components implement VRRP, OSPF/BGP, DHCP,
   RADIUS/RadSec, and multicast functions. A provider adapter renders validated
   configuration, supervises lifecycle, reads structured status, and reports failures.
   Exact providers and packaging are selected in phase research and recorded in the
   implementation plan.
3. **Shared network model:** named WANs, LANs, VPNs, virtual networks, physical
   interfaces, aggregates, addresses, routes, policies, and service attachments have
   stable identities. Validation rejects conflicting interface ownership and invalid
   references before apply.
4. **Management surface:** the existing authenticated admin portal gains configuration
   and operational views. Secrets are write-only. Apply reports validation errors,
   progress, effective state, and rollback outcome.
5. **Observability:** health/outage history, traffic flows, MAC table occupancy, DHCP,
   NAT, routing neighbors/routes, HA role, LACP members, and QoS counters use a common
   timestamped status/event model with bounded storage.

## Apply and failure behavior

- Validate the complete proposed configuration and required host capabilities before
  changing live networking.
- Stage provider configurations, run their native validation, and retain the last known
  good snapshot. Apply changes in dependency order and verify effective state.
- If a stage fails, restore the prior configuration and report both the failed stage and
  rollback result. Never report success based only on writing a config file.
- Keep management access reachable during a failed apply where possible. Changes to the
  interface carrying the management session require an explicit recovery strategy in the
  plan.
- Provider crash or peer loss is reported as degraded state; it must not silently remove
  unrelated routes, firewall rules, or services.
- Metrics and flow/event storage have explicit size and retention limits.

## Delivery sequence

Each group is a separate implementation phase with its own detailed plan, acceptance
checks, and dependency research. The sequence may be adjusted only when phase research
shows a prerequisite.

1. **Control-plane foundation and reporting:** capability inventory, common network
   model, safe validate/apply/rollback, authenticated configuration/status integration,
   WAN quality/outage history, all traffic flows, and MAC table limits/occupancy.
2. **Forwarding and policy:** customizable DHCP, advanced NAT, policy-based WAN/VPN
   routing, and QoS mapped to the Linux traffic-control layer.
3. **Redundancy and aggregation:** VRRP shadow/standby mode, health tracking, LACP
   configuration and state, and LTE backup as an additional managed WAN.
4. **Dynamic routing:** OSPF and BGP neighbors, route filters, route visibility, and
   controlled interaction with policy routing and VPN routes.
5. **LAN services and identity:** mDNS, IGMP proxy, integrated RADIUS, RadSec, and
   virtual-network override with isolation and authorization rules.

The first implementation phase must prove the host/container boundary and safe apply
mechanism before any feature mutates live host networking. The existing local-network
Layer 3 design should be reconciled with this shared network model before phases that
change DHCP or interface ownership.

## Acceptance criteria

1. The Linux gateway has a strict, versioned configuration contract and reports which
   requested features are available on the current host.
2. Invalid or unsupported configuration is rejected before live state changes; a failed
   apply restores the previous known-good state or clearly reports that recovery failed.
3. Every capability in scope has an explicit configuration, status, and failure model;
   no feature is reported as available when only a UI placeholder or config file exists.
4. Interface ownership conflicts among WANs, LANs, LACP, VRRP, VPNs, and multicast
   services are rejected with actionable errors.
5. VRRP role transitions, LACP member state, OSPF/BGP adjacencies and accepted routes,
   DHCP leases, NAT counters, QoS counters, multicast state, RADIUS/RadSec health, LTE
   status, flow records, outage history, and MAC table occupancy are observable.
6. Flow records and credentials respect configured access and retention controls; secrets
   never appear in API responses, logs, or status exports.
7. The legacy GameBond tunnel server and its existing deployments continue to work when
   the Linux router gateway is not enabled.

## Open decisions for phase research

- Which Linux distributions and install modes are supported, and whether the gateway
  runs directly on the host or in a dedicated privileged network namespace/container.
- Exact provider choices and package/version policy for routing, DHCP, VRRP, RADIUS,
  multicast, and LTE modem integration.
- Whether the first release supports IPv6, VLAN trunks, and multiple LAN networks.
- The intended meaning of “MAC Address Table Size” for target hardware and bridges.
- Whether “Virtual Network Override” selects a device's network, overrides a policy
  result per flow, or supports both with precedence rules.
- Which RadSec role is required (outbound client, inbound listener, or both).
- Flow record detail, retention defaults, export formats, and privacy requirements.
- Whether VRRP peers share conntrack/NAT state, and the exact failover guarantees.
