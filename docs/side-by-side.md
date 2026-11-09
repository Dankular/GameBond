# GameBond and OpenMPTCProuter side by side

One client, one VPS, two tunnels. Gameplay and calls keep using GameBond's own
tunnel, with everything that makes it stable on bad links: replicated copies
with dedupe, deadline queues that drop stale packets, adaptive redundancy and
link-quality scoring. Bulk traffic uses OpenMPTCProuter through its Glorytun UDP
tunnel. A stateful NAT gives that leg the OMR tunnel address.

```
 PS5 (10.77.0.3) -+                      +- DSCP 46 / 26 --> GameBond tunnel --> GameBond server (replicate, dedupe)
 PC apps (.2) ----+-> flow classifier ----+
                                          +- everything else -> NAT -> Glorytun UDP -> OMR server
```

## Why two tunnels

The OMR server stripes packets without sequence numbers and cannot dedupe. A
client alone could not replicate a game packet over OMR without it reaching the
game server twice, nor reorder or dedupe what OMR sends back. GameBond's server
does both, so it carries the traffic that needs them.

## Configuration

```json
"server_type": "both",
"omr": {
  "server": ["VPS_IP", 65001],
  "key_file": "secrets/glorytun.key",
  "tunnel_ip": "10.255.254.2",
  "rate_mbps": 100,
  "beat_ms": 100,
  "gamebond_dscp": [46, 26]
}
```

- `key_file`: the 64-hex-character Glorytun key (`GLORYTUN_PASS` on the VPS).
- `tunnel_ip`: the address the NAT presents to OMR (OMR's router default).
- `gamebond_dscp`: classes sent over the GameBond tunnel. Gameplay is 46 and
  calls 26; streams (18) and bulk (0) go to OMR by default.
- `beat_ms`: control-message interval; a lower value detects a dead link sooner.
- Needs `pip install 'gamebond[omr]'`. Server-side setup:
  [omr-server.md](omr-server.md). Test the OMR leg first with
  `tools/probe_omr_glorytun.py` ([omr-client.md](omr-client.md)).

`server_type: "omr"` alone is refused for now.

## Behavior

- A flow stays on one transport. If that transport stops being ready, the flow
  is moved to the other (a TCP connection breaks once instead of stalling),
  and stays there until idle for 120 s.
- Bulk falls back to the GameBond tunnel when OMR is down; gameplay falls back
  to OMR (without replication) when the GameBond tunnel is down.
- NAT: port-restricted cone, keeps the host's own port when free, TCP/UDP/ICMP
  echo and ICMP errors about TCP/UDP flows. Fragments, other ICMP types and
  other protocols are dropped and counted. UDP mappings idle out after 120 s,
  established TCP after 2 hours.
- Link roles, caps and usage metering apply to the GameBond leg only; the OMR
  leg does not yet feed them.
- The OMR leg opens its sockets on the uplink addresses present at connect
  time, without interface pinning, and does not follow adapter changes.
  Reconnect after changing uplinks. Overlapping LAN subnets on several uplinks
  are not handled on that leg.

## Verification status

Verified here (`tests/test_nat.py`, `tests/test_transport_router.py`,
`tests/test_side_by_side.py`, `tests/test_omr_settings.py`): NAT translation
and checksums against an independent full recompute (including forced port
changes), routing split, stickiness, fallback in both directions, return
traffic for both transports, and the whole path from a simulated PS5 through the
real runtime, a real GameBond server, and a Glorytun UDP peer.

**Not verified**: interoperability of the OMR leg with a real OMR server (the
peer in the tests is written from the same reading of the protocol; see
[omr-client.md](omr-client.md)), anything on Windows, and real game behavior
under link failures.
