# Running OpenMPTCProuter and the GameBond server on one VPS

Direction: the VPS runs OpenMPTCProuter's server (OMR) **and** GameBond's Python
server container. The GameBond client later chooses which one to talk to. This
page covers only the server host. The OMR client transport is not built yet.

## Why it needs care

OMR's installer assumes it owns the machine (read from `openmptcprouter-vps`):

- Its `/etc/nftables.conf` starts with `flush ruleset`, deleting every table,
  including Docker's NAT and forward rules, on install and every nftables reload.
- It installs an OMR kernel (reboot required) on a normal VPS, upgrades Debian 12
  to 13 by default, moves SSH from port 22 to 65222, forces IP forwarding on,
  and uses ports 65000-65535 for its tunnels.
- Its input and forward chains end in `reject`, so UDP 4433 and Docker bridge
  traffic are refused unless allowed.

## Setup

1. Install OMR on the VPS with its own installer and read its output
   (`/root/openmptcprouter_config.txt`). Reboot into the OMR kernel.
2. Install Docker and this repository on the same host.
3. Copy the GameBond rules into OMR's supported extension directory:
   ```sh
   install -m 0644 deploy/omr-coexist/gamebond.nft /etc/nftables/custom.d/gamebond.nft
   systemctl reload nftables
   ```
   `custom.d` is included after the OMR ruleset and the installer never touches
   it, so this survives OMR updates. The file publishes UDP 4433 to the container
   through OMR's own `custom_dnat_bypass` chain (which also keeps OMR's bulk
   port-redirect toggle from taking that port) and inserts the forward accepts
   ahead of OMR's final `reject`.
4. Start GameBond with the pinned bridge and address:
   ```sh
   docker compose --env-file deploy.env -f compose.yaml -f deploy/omr-coexist/compose.override.yaml up -d
   ```
   Container egress is masqueraded by OMR's own rule for `172.16.0.0/12`.

The rules are self-contained in OMR's ruleset, so nothing needs to be restarted
after an nftables reload. The ports do not overlap: GameBond uses UDP 4433,
OMR uses 65000-65535 and its admin API on 65500.

## Check before deploying

```sh
tools/check-omr-coexistence.sh /path/to/openmptcprouter-vps
```

Runs `nft -c` (parse only, loads nothing) on OMR's real ruleset with and without
the GameBond file, plus a deliberately broken file that must be rejected.

## Verification status

Verified: the ruleset parses together with OMR's current `nftables.conf`,
`omr.nft` and `omr-vars.nft` (checked 2026-11-09 against the clone read for this work).

**Not verified**, needs a real VPS:

- That UDP 4433 actually reaches the container and back with OMR running.
- Docker on the OMR kernel (bridge, overlay and netfilter modules), and the
  interaction of Docker's own iptables rules with OMR's table when both exist.
- That OMR's installer completes on your VPS image with Docker already present.
- IPv6: the rules are IPv4 only.
- The compose override was parsed as YAML but not run through `docker compose`.
