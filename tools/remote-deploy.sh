#!/bin/sh
# Dedicated Docker namespace only; preserves existing WireGuard/services.
set -eu
umask 077
session=5fbd6b092d1dfc85849a92eb4a286092
archive=/root/gamebond-deployment-$session.tar.gz
release=/opt/gamebond/releases/$session
test -f "$archive"
test ! -e "$release"
test -c /dev/net/tun
if ss -H -u -l -n | awk '{print $4}' | grep -Eq '(^|:)4433$'; then
    echo 'UDP4433 already in use; refusing collision' >&2
    exit 1
fi
available=$(df -Pk /var/lib/docker | awk 'NR==2 { print $4 }')
if [ "$available" -lt 1048576 ]; then
    echo 'Less than 1GiB disk free; refusing image build without changing existing data' >&2
    exit 1
fi
mkdir -p /opt/gamebond/releases
mkdir -m 700 "$release"
tar -xzf "$archive" -C "$release" --no-same-owner
chmod 700 "$release/secrets"
chmod 600 "$release/secrets/gamebond.key"
rm -f "$archive"
cd "$release"
docker ps --format '{{.Names}}' > existing-containers-before.txt
docker compose --env-file deploy.env config --quiet
docker compose --env-file deploy.env build
docker compose --env-file deploy.env up -d --no-build
docker compose --env-file deploy.env ps
docker compose --env-file deploy.env logs --tail 30
printf 'DEPLOYED_RELEASE=%s\n' "$release"
printf 'Rollback only this project: cd %s && docker compose --env-file deploy.env down\n' "$release"
