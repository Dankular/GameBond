#!/bin/sh
set -eu
printf 'COMPOSE\n'
docker compose version
printf 'MEMORY\n'
free -m
printf 'DISK\n'
df -h / /var/lib/docker
printf 'LISTENERS\n'
ss -uln | awk 'NR==1 || /:4433[[:space:]]/ || /:51820[[:space:]]/'
printf 'WIREGUARD_INTERFACES\n'
if command -v wg >/dev/null 2>&1; then wg show interfaces; fi
printf 'HOST_FORWARDING\n'
cat /proc/sys/net/ipv4/ip_forward
printf 'GAMEBOND_EXISTING\n'
docker ps -a --filter label=com.docker.compose.project=gamebond --format '{{.Names}} {{.Status}} {{.Ports}}'
