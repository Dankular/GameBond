# Current status

Reviewed 2026-11-05 against source and retained local results.
These are completed checks, not a live process or server status.
Raw diagnostics and live configs are excluded from Git.

## Verified

- Captured HTTPS and HTTP/3 exited through the VPS with both links healthy.
- 96 simultaneous HTTPS connections completed 192 requests and reused the
  same sockets after 11 seconds idle.
- A 65-second All apps check allowed 55 connections with zero authorization
  rejections/errors. The real Codex process transferred traffic.
- Protected-process creation times matched psutil for 97 processes; invalid
  PIDs were rejected. Executable authorization still independently verifies identity.
- 293 Python tests passed after GUI optimization; prior netstack Go checks passed.
- Native Linux TUN integration passed isolated VPS HTTPS and UDP egress tests.

## Remaining gaps

| Area | Remaining work |
| --- | --- |
| Aggregation | Repeated single-link versus combined-link upload/download tests. A short physical comparison showed combined goodput below the faster link; useful speed gains remain unproven. |
| QoS | Long game/call/stream sessions during downloads and real outages; asymmetric links, per-flow fairness, and first-SYN priority. |
| Limits | Deployed cap exhaustion, billing rollover, directional enforcement, and complete TCP/TLS overhead accounting. |
| Coverage | Explicit system DNS/IPv6 handling and optional machine-wide failure protection. IPv4 app capture is not a kill switch. |
| Fallback | Production relay activation/configuration. Isolated fallback/recovery checks already passed. |
| Native server | Production integration, mixed-traffic compatibility, and physical performance validation. Linux TUN egress is already implemented and tested. |
| Security/delivery | Automatic protocol/key rotation, forward secrecy, multi-client support, path MTU discovery, and a packaged installer. |
| Observability | Complete directional loss/overhead accounting and clear app-payload versus tunnel/adapter metrics. |

Adaptive QoS, application profiles, link roles, persistent usage tracking,
adapter rebinding, and fallback carriers exist. Their endurance, enforcement,
and rollout checks above remain incomplete.

## Recent fixes

- Increased proxy connection capacity from 64 to 1,024.
- Stopped oversized telemetry from terminating the packet reader.
- Fixed service-name/path verification and protected-process birth-time lookup.

These fixes establish connectivity, not proven physical aggregation or match continuity.
