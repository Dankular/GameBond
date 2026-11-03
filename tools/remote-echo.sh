#!/bin/sh
set -eu
docker exec -i gamebond-server-1 sh -c 'cat > /tmp/gamebond-echo.py' <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.bind(('10.77.0.1', 9009))
    while True:
        packet, peer = udp.recvfrom(1401)
        if peer[0] == '10.77.0.2' and len(packet) <= 1400:
            udp.sendto(packet, peer)
PY
docker exec -d gamebond-server-1 timeout 300s python /tmp/gamebond-echo.py
docker exec gamebond-server-1 sh -c "ss -H -u -l -n | grep ':9009 '"
printf 'TEMPORARY_TUNNEL_ECHO_READY_300_SECONDS\n'
