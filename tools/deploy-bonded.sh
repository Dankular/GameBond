#!/bin/sh
# Update this Compose project only; all tunnel/NAT work stays in its namespace.
set -eu
umask 077
session=c9550b78e96dc3d0fdc1d3b6a894bd22
archive=/root/gamebond-bonded-$session.tar.gz
release=/opt/gamebond/releases/$session
test -f "$archive"
test ! -e "$release"
test "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' gamebond-server-1)" = gamebond
old_release=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' gamebond-server-1)
case "$old_release" in /opt/gamebond/releases/*) ;; *) echo 'Unexpected existing release path' >&2; exit 1;; esac
test -f "$old_release/deploy.env"
mkdir -m 700 "$release"
tar -xzf "$archive" -C "$release" --no-same-owner
chmod 700 "$release/secrets"
chmod 600 "$release/secrets/gamebond.key"
cd "$release"
docker ps --format '{{.Names}}' | sed '/^gamebond-server-1$/d' | sort > other-containers-before.txt
wg show interfaces > wireguard-before.txt
docker compose --env-file deploy.env config --quiet
docker compose --env-file deploy.env build
rollback() {
    echo 'Bonded startup failed; restoring previous GameBond release' >&2
    cd "$old_release"
    docker compose --env-file deploy.env up -d --no-build
}
if ! docker compose --env-file deploy.env up -d --no-build; then rollback; exit 1; fi
attempt=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' gamebond-server-1)" = healthy ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 30 ]; then
        docker logs --tail 20 gamebond-server-1
        rollback
        exit 1
    fi
    sleep 1
done
docker ps --format '{{.Names}}' | sed '/^gamebond-server-1$/d' | sort > other-containers-after.txt
wg show interfaces > wireguard-after.txt
diff other-containers-before.txt other-containers-after.txt
diff wireguard-before.txt wireguard-after.txt
docker exec gamebond-server-1 python -c 'from gamebond import __version__; from gamebond.app import load_config; c=load_config("/run/config/server.json"); assert __version__ == "0.3.0" and c["bonding_mode"]; print("version="+__version__+" bonding_mode=true")'
docker inspect --format '{{.Config.Image}} {{.State.Status}} {{.State.Health.Status}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}}' gamebond-server-1
docker logs --tail 2 gamebond-server-1
printf 'UPDATED_RELEASE=%s\n' "$release"
