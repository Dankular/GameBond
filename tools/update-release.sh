#!/bin/sh
set -eu
umask 077
session=$1
version=$2
case "$session" in *[!0-9a-f]*) exit 2;; esac
case "$version" in *[!0-9.]*|'') exit 2;; esac
test "${#session}" -eq 32
release=/opt/gamebond/releases/$session
archive=/root/gamebond-$version-$session.tar.gz
test -f "$archive"
test ! -e "$release"
test "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' gamebond-server-1)" = gamebond
old_release=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' gamebond-server-1)
case "$old_release" in /opt/gamebond/releases/*) ;; *) exit 2;; esac
mkdir -m 700 "$release"
tar -xzf "$archive" -C "$release" --no-same-owner
chmod 700 "$release/secrets"
chmod 600 "$release/secrets/gamebond.key"
cd "$release"
docker ps --format '{{.Names}}' | sed '/^gamebond-server-1$/d' | sort > other-containers-before.txt
docker compose --env-file deploy.env config --quiet
docker compose --env-file deploy.env build
rollback() { cd "$old_release"; docker compose --env-file deploy.env up -d --no-build; }
if ! docker compose --env-file deploy.env up -d --no-build; then rollback; exit 1; fi
attempt=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' gamebond-server-1)" = healthy ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 45 ]; then docker logs --tail 10 gamebond-server-1; rollback; exit 1; fi
    sleep 1
done
docker ps --format '{{.Names}}' | sed '/^gamebond-server-1$/d' | sort > other-containers-after.txt
diff other-containers-before.txt other-containers-after.txt
docker exec -e GAMEBOND_EXPECTED_VERSION="$version" gamebond-server-1 python -c 'import os;from gamebond import __version__;from gamebond.transport import BOND_MAGIC;assert __version__==os.environ["GAMEBOND_EXPECTED_VERSION"] and BOND_MAGIC==b"GB03";print("version="+__version__+" protocol=GB03")'
docker inspect --format '{{.Config.Image}} {{.State.Status}} {{.State.Health.Status}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}}' gamebond-server-1
printf 'UPDATED_RELEASE=%s\n' "$release"
