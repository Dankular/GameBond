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

Use the **OpenMPTCProuter** button in the dashboard (or the settings menu), or edit the config:

```json
"server_type": "both",
"omr": {
  "server": ["VPS_IP", 65001],
  "admin": {
    "username": "openmptcprouter",
    "password_file": "secrets/omr-admin.pass",
    "pin": "sha256//BASE64_SPKI_SHA256"
  },
  "rate_mbps": 100,
  "beat_ms": 100,
  "gamebond_dscp": [46, 26]
}
```

- Key source, exactly one of: `admin` (the client logs in to the OMR admin API
  on port 65500 and reads the Glorytun key and tunnel address from `/config`) or
  `"key_file": "secrets/glorytun.key"` (the 64-hex-character key, `GLORYTUN_PASS`
  on the VPS).
- `admin.pin`: the base64 SHA-256 of the server's public key, the same value
  OMR's own router pins (the VPS installer prints it). The dialog's **Read from
  server** shows it for you to compare and confirm; it is never trusted
  silently, and **no credentials are sent before a pin is configured**. A
  refused login is attempted once and never retried automatically (the server
  bans an address after six failures). The password lives in the file named by
  `password_file`, never in the config.
- `tunnel_ip`: the address the NAT presents to OMR. Left out, it is taken from
  the server (`glorytun.udp.client_ip`, usually 10.255.254.2); set it to override.
- `gamebond_dscp`: classes sent over the GameBond tunnel. Gameplay is 46 and
  calls 26; streams (18) and bulk (0) go to OMR by default.
- `beat_ms`: control-message interval; a lower value detects a dead link sooner.
- Needs `pip install 'gamebond[omr]'`. Server-side setup:
  [omr-server.md](omr-server.md). Test the OMR leg first with
  `tools/probe_omr_glorytun.py` ([omr-client.md](omr-client.md)).

`server_type: "omr"` alone is refused for now.

## Bad links on the OMR leg

GameBond's replicate-and-dedupe cannot run over OMR, so the OMR leg gets what a
client can do alone, modelled on how Speedify documents its behavior (per-link
latency monitoring, backup links, per-link limits):

- **Fast failure detection.** A path that misses two control echoes (about 40 ms
  at `beat_ms` 20, 200 ms at the default 100) is treated as suspect at once;
  urgent traffic never uses it.
- **Urgent traffic uses one path.** Traffic that falls back onto OMR from the
  GameBond classes is sent on the single best path (lowest estimated latency),
  not striped.
- **Steering the server's side too.** A path whose RTT spikes against its own
  baseline, or whose jitter or loss rises, is demoted after 0.3 s by advertising
  a worse preference. The server copies the preference from every control
  message, so downstream traffic leaves that link as well. It is restored only
  after 3 s of sustained health. Nothing is demoted when no better path exists.
- **Hot standby.** A `backup` link is probed cheaply (about 4 per second) so its
  quality is known and it takes over without a reconnect when the primary fails.
- **Link roles and speed limits** from "Link roles & limits" apply to this leg:
  primary and secondary aggregate, backup is standby, never (or over a data cap)
  removes the link; upload limits cap sending and download limits are advertised
  to the server.
- **Adapter changes.** Only the changed uplink is rebound, and its socket is pinned to
  the Windows interface the same way the GameBond transport does it.

Not possible without a server component: downstream replication, dedupe and
reordering. During the detection window a degrading link can still lose some
downstream packets.

## If the OMR leg fails

The GameBond tunnel never depends on it. If the admin login, key fetch or the
tunnel itself fails, GameBond keeps running on its own tunnel, the dialog shows
the reason, and the leg is retried every 30 seconds (except after a refused
login). Bulk traffic uses the GameBond tunnel meanwhile.

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
- Link roles and speed limits apply to both legs. Usage metering and data caps
  count the GameBond leg only; OMR bytes do not feed them yet (a link over its
  cap is still removed from both).

## Verification status

Verified here (`tests/test_nat.py`, `tests/test_transport_router.py`,
`tests/test_side_by_side.py`, `tests/test_omr_settings.py`): NAT translation
and checksums against an independent full recompute (including forced port
changes), routing split, stickiness, fallback in both directions, return
traffic for both transports, and the whole path from a simulated PS5 through the
real runtime, a real GameBond server, and a Glorytun UDP peer.

Also verified (`tests/test_omr_steering.py`, `test_omr_admin.py`,
`test_omr_runtime.py`, `test_omr_dialog.py`): dead-link and latency-spike
handling with demotion and recovery, hot standby takeover, adapter rebinding,
speed limits reaching the server, the admin client against a fake HTTPS server
(pin matching, no data on a wrong key, single login attempt), the runtime
degrading safely, and the dialog.

**Not verified**: interoperability of the OMR leg with a real OMR server (the
peer and the fake admin server in the tests are written from the same reading of
the source; see [omr-client.md](omr-client.md)), interface pinning on Windows
(it mirrors the GameBond transport's code but has not been run there), and real
game behavior under link failures. The steering thresholds (2x RTT + 20 ms,
8 ms jitter, 2% loss, 0.3 s to demote, 3 s to restore) are starting values, not
measured ones.
