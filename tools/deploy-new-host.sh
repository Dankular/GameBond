#!/bin/sh
set -eu
umask 077
session=d38278f430021fe9169d99f21730ee93
release=/opt/gamebond/releases/$session
archive=/root/gamebond-$session.tar.gz
test -c /dev/net/tun
test -f "$archive"
test ! -e "$release"
test -z "$(docker ps -a --filter name='^/gamebond-server-1$' --format '{{.Names}}')"
mkdir -p /opt/gamebond/releases
mkdir -m 700 "$release"
tar -xzf "$archive" -C "$release" --no-same-owner
chmod 700 "$release/secrets"
chmod 600 "$release/secrets/gamebond.key"
cd "$release"
docker ps --format '{{.Names}}' | sort > other-containers-before.txt
docker compose --env-file deploy.env config --quiet
docker compose --env-file deploy.env build
docker compose --env-file deploy.env up -d --no-build
attempt=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' gamebond-server-1)" = healthy ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 45 ]; then docker logs --tail 20 gamebond-server-1; exit 1; fi
    sleep 1
done
docker ps --format '{{.Names}}' | sed '/^gamebond-server-1$/d' | sort > other-containers-after.txt
diff other-containers-before.txt other-containers-after.txt
docker exec gamebond-server-1 python -c 'from gamebond import __version__;from gamebond.app import load_config;c=load_config("/run/config/server.json");assert __version__=="0.3.1" and c["bonding_mode"];print("version="+__version__+" bonding_mode=true")'
docker inspect --format '{{.Config.Image}} {{.State.Status}} {{.State.Health.Status}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}}' gamebond-server-1
printf 'UPDATED_RELEASE=%s\n' "$release"
