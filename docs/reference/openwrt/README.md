# OpenWrt / LuCI reference (design input only)

Used to shape the navigation and page layout of the GameBond admin portal.
Nothing here is shipped in the portal or the container image; the portal's
HTML/CSS/JS is written from scratch.

## Sources (fetched 2026-11-09)

- `luci-menu/*.json`: LuCI menu definitions from
  `https://raw.githubusercontent.com/openwrt/luci/master/modules/luci-mod-{status,system,network}/root/usr/share/luci/menu.d/`
  and `luci-base`. These define the top-level tabs (Status, System, Services,
  Network, VPN, Log out) and their children. LuCI is open source; the licence
  text was not re-checked here, so check it before copying anything further.
- `screenshots/`: five PNGs from the OpenWrt wiki page
  `https://openwrt.org/docs/guide-quick-start/walkthrough_login`
  (`/_media/media/doc/walkthrough-*.png`). **Licence of these images not verified.**
  They show LuCI from OpenWrt 14.07 (Barrier Breaker); they are the old
  look, not current LuCI themes. No current-theme screenshots were fetched.

## Navigation mapping

| LuCI | GameBond portal |
| --- | --- |
| Status > Overview | Status > Overview |
| Status > Routing | Network > Routing (`ip route`) |
| Status > Firewall | Status > Firewall (NAT) (`nft list table ip gamebond`) |
| Status > System Log | Status > System Log (portal events and uplink health only) |
| Status > Realtime Graphs | Status > Realtime Graphs (bandwidth only) |
| Network > Interfaces | Network > Interfaces (`ip addr`) |
| Network > DHCP | Network > Connected Devices (configured addresses only) |
| System > Administration | System > Administration (password) |
| System > Backup / Flash | System > Configuration (edit, validate, save) |
| System > Reboot | System > Restart Service |
| (none) | Status > Uplinks, Status > QoS & Queues (GameBond-specific) |

LuCI items with no GameBond equivalent (Wireless, Switch, Software, LEDs, Mount
Points, Scheduled Tasks, Diagnostics, DNS/DHCP server settings) were left out.
