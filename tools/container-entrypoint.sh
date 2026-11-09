#!/bin/bash
# All commands operate in the container's private network namespace. The
# Compose service supplies NET_ADMIN, /dev/net/tun and namespaced forwarding.
set -euo pipefail

CONFIG=/run/config/server.json
KEY=/run/secrets/gamebond.key
child=
nat_added=0

cleanup() {
    status=$?
    trap - EXIT TERM INT
    rm -f /tmp/gamebond-ready /tmp/gamebond.pid
    if [[ -n "$child" ]]; then
        kill -TERM "$child" 2>/dev/null || true
        # Give the Python signal handler time to close packet workers and TUN.
        for ((attempt=0; attempt<50; attempt++)); do
            if ! kill -0 "$child" 2>/dev/null; then break; fi
            sleep 0.1
        done
        if kill -0 "$child" 2>/dev/null; then kill -KILL "$child" 2>/dev/null || true; fi
        wait "$child" 2>/dev/null || true
    fi
    if [[ $nat_added == 1 ]]; then nft delete table ip gamebond 2>/dev/null || true; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

[[ -c /dev/net/tun ]] || { echo '/dev/net/tun device is required' >&2; exit 1; }
[[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]] || {
    echo 'Container requires namespaced net.ipv4.ip_forward=1 from Compose' >&2; exit 1;
}
# Validate the fixed container topology before creating any device or nft rule.
python - "$CONFIG" "$KEY" <<'PY'
import sys
from pathlib import Path
from gamebond.app import load_config
c = load_config(sys.argv[1])
if (c['role'] != 'server' or c['bind'] != [['0.0.0.0', 4433]] or
        c.get('tun_name', 'GameBond') != 'gamebond0' or
        c.get('mtu', 1280) != 1280 or c['client_tunnel_ip'] != '10.77.0.2'):
    raise SystemExit('Container config must use server, 0.0.0.0:4433, gamebond0, MTU1280 and client 10.77.0.2')
if len(Path(sys.argv[2]).read_bytes()) != 32:
    raise SystemExit('The read-only shared key must contain exactly 32 bytes')
PY

# Attached LAN devices (for example a console behind a client USB adapter) each get their
# own tunnel address. Without any, the original lone-client /30 and single-source NAT stay.
LAN_IPS=$(python - "$CONFIG" <<'PY'
import sys
from gamebond.app import load_config
print(' '.join(load_config(sys.argv[1]).get('lan_tunnel_ips', [])))
PY
)
TUNNEL_PREFIX=30
NAT_SOURCES='10.77.0.2/32'
if [[ -n "$LAN_IPS" ]]; then
    [[ ${GAMEBOND_NATIVE_EDGE:-0} != 1 ]] || {
        echo 'lan_tunnel_ips are supported by the Python server only; unset GAMEBOND_NATIVE_EDGE' >&2; exit 1;
    }
    for lan_ip in $LAN_IPS; do
        [[ "$lan_ip" =~ ^10\.77\.0\.([3-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])$ ]] || {
            echo "LAN device address $lan_ip must be 10.77.0.3 to 10.77.0.254" >&2; exit 1;
        }
    done
    TUNNEL_PREFIX=24
    NAT_SOURCES="{ 10.77.0.2, ${LAN_IPS// /, } }"
fi

NFT_TABLES=$(nft list tables)
if grep -Fxq 'table ip gamebond' <<< "$NFT_TABLES"; then
    echo 'Container gamebond nft table already exists; refusing overwrite' >&2; exit 1
fi
[[ ! -e /sys/class/net/gamebond0 ]] || { echo 'gamebond0 already exists; refusing reuse' >&2; exit 1; }
WAN=$(ip -4 route show default | awk 'NR == 1 { for (i=1;i<NF;i++) if ($i == "dev") {print $(i+1); exit} }')
[[ "$WAN" =~ ^[a-zA-Z0-9_.:-]+$ && "$WAN" != gamebond0 ]] || {
    echo 'No valid container bridge egress interface found' >&2; exit 1;
}

if [[ ${GAMEBOND_NATIVE_EDGE:-0} == 1 ]]; then
    /usr/local/bin/gamebond-native-edge --config "$CONFIG" --key "$KEY" &
else
    python -m gamebond run "$CONFIG" --key "$KEY" &
fi
child=$!
printf '%s\n' "$child" > /tmp/gamebond.pid
# The packet process creates TUN. Bound startup wait to ten seconds and fail
# promptly when the child exits rather than configuring an unrelated device.
for ((attempt=0; attempt<100; attempt++)); do
    if ! kill -0 "$child" 2>/dev/null; then
        wait "$child" || exit $?
        echo 'GameBond exited during startup' >&2; exit 1
    fi
    if [[ -e /sys/class/net/gamebond0 ]]; then break; fi
    sleep 0.1
done
[[ -e /sys/class/net/gamebond0 ]] || { echo 'Timed out waiting for gamebond0' >&2; exit 1; }
ip address add "10.77.0.1/$TUNNEL_PREFIX" dev gamebond0
ip link set dev gamebond0 mtu 1280 up
nft -f - <<EOF
add table ip gamebond
add chain ip gamebond postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule ip gamebond postrouting ip saddr $NAT_SOURCES oifname "$WAN" masquerade
EOF
nat_added=1
kill -0 "$child"
touch /tmp/gamebond-ready
echo 'GameBond container locally ready; client reachability has not been measured'
wait "$child"
