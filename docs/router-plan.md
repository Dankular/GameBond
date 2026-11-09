# Router behavior in GameBond: plan

Direction: GameBond's userspace becomes the router environment for the
workstation and the devices behind it, on GameBond's own protocol. It does not
interoperate with OpenMPTCProuter's data plane (MPTCP kernel stack with
Shadowsocks/Glorytun and others) and does not reuse its code (GPL-3.0). OMR is
a reference for the feature set only.

Platform: Windows first, because that is the only runtime that exists. The
Linux frame I/O backend is already there; a Linux runtime is not.

## Phases

| # | Piece | State |
|---|---|---|
| 1 | Connected devices: DHCP, ARP, own tunnel address, forwarding ([lan-devices.md](lan-devices.md)) | done |
| 2 | DNS for connected devices: configured names answered in-line | done, this change |
| 3 | Router config model: LAN, DHCP reservations, DNS, routing policy, forwards; the DNS tab grows into a Router tab | planned |
| 4 | Port forwards: DNAT on the VPS, managed from the UI (fixes the inbound limit) | planned |
| 5 | Routing policy by domain, IP or port: via the bond, a chosen uplink, or direct | planned; "direct" needs workstation NAT, which does not exist |
| 6 | A small subnet behind a switch: DHCP pool, per-host MAC table, `lan_tunnel_ips` as a range | planned |

Order after phase 2 is open: ports before policy is cheaper, policy is the
larger feature.
