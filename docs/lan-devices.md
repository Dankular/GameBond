# Connected devices (console on a USB adapter)

A device such as a PS5 can join the bond through a spare network adapter on the
workstation. The adapter is dedicated to that device: GameBond answers its
DHCP and ARP requests, gives it its **own address on the bond network**
(for example `10.77.0.3`), and forwards its traffic through the same bonded
links, queues and priority rules as the workstation's own traffic. The VPS
sees and NATs that address separately from the workstation's `10.77.0.2`.

```
PS5 --ethernet-- USB adapter (GameBond gateway) --+
                                                  +-- Starlink / 5G / ... bond --> VPS --> internet
Workstation apps ---------- netstack -------------+
```

## Setup

1. Plug the PS5 into a spare adapter. Set the PS5 to automatic (DHCP) network
   settings. Leave the adapter itself unconfigured; GameBond takes it over.
2. **Server:** add the device address(es) to the server config and restart it.
   The container then uses a `/24` tunnel subnet and NATs each listed address.
   ```json
   "lan_tunnel_ips": ["10.77.0.3"]
   ```
   Without this key nothing changes (`/30`, one NAT source). Outside Docker,
   set `GAMEBOND_LAN_IPS="10.77.0.3"` when running `tools/linux-network.sh`.
3. **Client:** open **Connected devices** in the dashboard, tick the adapter,
   name the device and keep or change its address, then save. This writes
   `lan_devices` (a manual example follows). Reconnect the tunnel.
   ```json
   "lan_devices": [{
     "name": "PS5",
     "tunnel_ip": "10.77.0.3",
     "interface_id": "{ADAPTER-GUID}",
     "interface_index": 14
   }]
   ```
   Optional per device: `device_mac` (pin one device; otherwise the first DHCP
   client wins and a different one is accepted only after 120 s of silence) and
   `dns` (default `1.1.1.1`, `8.8.8.8`). On Linux use `interface_name` instead of
   `interface_id`.
4. Power on the PS5. The dashboard dialog shows whether the adapter is up and
   whether the device has taken its address; the runtime status file carries
   per-device counters under `lan_devices`.

The device's address must be in the client tunnel `/24`, not `.0`, `.1` (VPS),
`.255` or the workstation's own address, and must also be in the server's
`lan_tunnel_ips`; the server drops any other source. An adapter cannot be both
a bonded uplink and a device adapter. Up to four devices are supported.

## Behavior

- Plain IPv4 forwarding, no NAT on the workstation. The PS5's default gateway
  is the VPS tunnel address; the workstation answers ARP for every tunnel
  address except the PS5's own.
- Packets are clamped to the tunnel MTU: TCP SYN MSS is lowered, oversized
  packets without DF are fragmented, and DF packets receive ICMP
  "fragmentation needed". The DHCP lease advertises MTU 1280.
- Device traffic is classified like workstation traffic, so `game_udp_ports`
  and the DSCP queues apply to it too.
- **Custom DNS** (the dashboard DNS tab) now applies to connected devices. A
  UDP/53 query from a device for a configured name is answered on the
  workstation, whichever resolver the device was told to use, and never
  leaves it; the answer follows the existing override rules (no fall-through,
  empty answer for other record types). Every other query goes through the
  tunnel untouched. Not covered: apps on the workstation itself, TCP DNS and
  encrypted DNS (DoH/DoT). Changes apply on reconnect.
- Multicast, broadcast and spoofed-source traffic from the device are not
  forwarded. IPv6 is not supported.
- Unplugging the adapter does not stop the tunnel. GameBond retries every five
  seconds.
- Inbound connections from the internet to the PS5 are **not** forwarded:
  nothing creates port forwards or UPnP mappings. Add `dnat` rules on the VPS
  yourself if you need them.

## Windows requirements

Raw frames come from the Windows Packet Filter driver that ProxiFyre already
needs, through `\\.\NDISRD`, in tunnel mode on the chosen adapter: Windows
stops seeing that adapter's traffic, and anything Windows tries to send out of
it is discarded. Requires 64-bit Python. If GameBond is killed rather than
stopped, the adapter may stay in tunnel mode until GameBond next starts or the
adapter is reset; the driver's behavior on abnormal exit was not verified.

## Verification status

Verified here (Linux container):

- Gateway logic (DHCP, ARP, forwarding, MSS/fragmentation/ICMP, spoof and
  foreign-device handling): `tests/test_lan_gateway.py`.
- Real kernel raw sockets against a TAP device: `tests/test_lan_gateway_linux_io.py`.
- Server accepts and routes back exactly the configured addresses:
  `tests/test_lan_server.py`.
- Full path simulated device -> gateway -> runtime -> encrypted transport ->
  server -> back, with the workstation's own traffic unaffected:
  `tests/test_lan_end_to_end.py`.
- `nft` accepts the generated NAT rule (dry run with `nft -c`).

**Not verified**, and needing a Windows machine or real hardware:

- The Windows Packet Filter backend against the real driver. Struct layouts and
  call order follow the upstream source (`wiresock/ndisapi`); the tests use a
  fake driver. In particular unverified: that the adapter list name is
  `\DEVICE\<adapter GUID>` for your adapter, the error behavior of an empty
  read queue, and driver behavior when the adapter is unplugged.
- The USB badge in the dialog (`Get-NetAdapter` `PnPDeviceID`); if it fails the
  adapters are simply listed without it.
- A real PS5: its DHCP options, ARP behavior with a `/24` and proxy ARP, and
  its tolerance of MTU 1280.
- Throughput, latency and game behavior over the bond, and the resulting NAT type.
- The native Go server (`GAMEBOND_NATIVE_EDGE=1`) does not support
  `lan_tunnel_ips`; it rejects unknown config keys, and the container refuses
  the combination.
