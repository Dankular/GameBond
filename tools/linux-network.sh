#!/usr/bin/env bash
# Reviewed commands only until --apply is explicitly supplied.
set -euo pipefail
WAN=${1:?Usage: linux-network.sh WAN_INTERFACE [--apply]}
if [[ ! "$WAN" =~ ^[a-zA-Z0-9_.:-]+$ ]]; then echo 'Invalid WAN interface' >&2; exit 1; fi
if [[ "$WAN" == gamebond0 ]]; then echo 'WAN must be separate from gamebond0' >&2; exit 1; fi
if [[ ${2:-} != --apply ]]; then
    printf 'Start the GameBond server first, then run as root:\n'
    printf 'ip address add 10.77.0.1/30 dev gamebond0\nip link set dev gamebond0 mtu 1280 up\nsysctl -w net.ipv4.ip_forward=1\n'
    printf 'nft add table ip gamebond\n'
    printf "nft 'add chain ip gamebond postrouting { type nat hook postrouting priority srcnat; policy accept; }'\n"
    printf "nft 'add rule ip gamebond postrouting ip saddr 10.77.0.2/32 oifname \"%s\" masquerade'\n" "$WAN"
    printf 'Also allow UDP/4433 INPUT and gamebond0 <-> %s FORWARD in your existing firewall; this script does not replace it.\n' "$WAN"
    exit 0
fi
[[ $EUID == 0 ]] || { echo 'Root required' >&2; exit 1; }
ip link show dev "$WAN" >/dev/null
ip link show dev gamebond0 >/dev/null
# Listing the complete inventories must succeed: a missing exact table is
# expected, but a permission/provider failure must stop before any changes.
NFT_TABLES=$(nft list tables)
if grep -Fxq 'table ip gamebond' <<< "$NFT_TABLES"; then echo 'gamebond nft table already exists; refusing overwrite' >&2; exit 1; fi
IPV4_ADDRESSES=$(ip -4 address show)
if grep -q '10\.77\.0\.1/' <<< "$IPV4_ADDRESSES"; then echo 'Tunnel address already exists on an interface' >&2; exit 1; fi
OLD_FORWARD=$(sysctl -n net.ipv4.ip_forward)
OLD_MTU=$(cat /sys/class/net/gamebond0/mtu)
OLD_FLAGS=$(cat /sys/class/net/gamebond0/flags)
OLD_UP=$((OLD_FLAGS & 1))
ADDRESS_ADDED=0
NAT_ADDED=0
rollback() {
    if [[ $NAT_ADDED == 1 ]]; then nft delete table ip gamebond 2>/dev/null || true; fi
    if [[ $ADDRESS_ADDED == 1 ]]; then ip address del 10.77.0.1/30 dev gamebond0 2>/dev/null || true; fi
    ip link set dev gamebond0 mtu "$OLD_MTU" 2>/dev/null || true
    if [[ $OLD_UP == 0 ]]; then ip link set dev gamebond0 down 2>/dev/null || true; fi
    sysctl -w net.ipv4.ip_forward="$OLD_FORWARD" >/dev/null || true
}
trap rollback ERR
ip address add 10.77.0.1/30 dev gamebond0
ADDRESS_ADDED=1
ip link set dev gamebond0 mtu 1280 up
sysctl -w net.ipv4.ip_forward=1
# One atomic nft transaction; quoted string reaches nft unchanged, including
# interface names containing dots/colons. WAN was constrained above.
nft -f - <<EOF
add table ip gamebond
add chain ip gamebond postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule ip gamebond postrouting ip saddr 10.77.0.2/32 oifname "$WAN" masquerade
EOF
NAT_ADDED=1
trap - ERR
echo 'Applied scoped NAT. Existing firewall must allow UDP/4433 and forwarding.'
printf 'Cleanup: nft delete table ip gamebond; stop GameBond; restore net.ipv4.ip_forward=%s if no other service needs forwarding.\n' "$OLD_FORWARD"
