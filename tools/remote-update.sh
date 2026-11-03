#!/bin/sh
# Upgrade only this Docker project. Existing WireGuard/other containers stay.
set -eu
umask 077
session=0cab6885a8c3cf4a44cc77d0ba494b93
archive=/root/gamebond-deployment-$session.tar.gz
release=/opt/gamebond/releases/$session
old_release=/opt/gamebond/releases/5fbd6b092d1dfc85849a92eb4a286092
test -f "$archive"
test ! -e "$release"
mkdir -m 700 "$release"
tar -xzf "$archive" -C "$release" --no-same-owner
chmod 700 "$release/secrets"
chmod 600 "$release/secrets/gamebond.key"
rm -f "$archive"
cd "$release"
docker compose --env-file deploy.env config --quiet
docker compose --env-file deploy.env build
if ! docker compose --env-file deploy.env up -d --no-build; then
    echo 'New container start failed; restoring previous image/config' >&2
    cd "$old_release"
    docker compose --env-file deploy.env up -d --no-build
    exit 1
fi
attempt=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' gamebond-server-1)" = healthy ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 30 ]; then docker compose --env-file deploy.env logs --tail 20; exit 1; fi
    sleep 1
done
docker inspect --format '{{.Config.Image}} {{.State.Status}} {{.State.Health.Status}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}}' gamebond-server-1
docker exec gamebond-server-1 sh -c 'ss -u -l -n -m; cat /proc/net/snmp | grep -A1 ^Udp:'
docker compose --env-file deploy.env logs --tail 3
wg show interfaces
printf 'UPDATED_RELEASE=%s\n' "$release"
