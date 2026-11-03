#!/bin/sh
set -eu
umask 077
release=/opt/gamebond/releases/5fbd6b092d1dfc85849a92eb4a286092
cd "$release"
printf 'PRODUCTION_HEALTH\n'
docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}} net={{.HostConfig.NetworkMode}} privileged={{.HostConfig.Privileged}} capadd={{json .HostConfig.CapAdd}} readonly={{.HostConfig.ReadonlyRootfs}}' gamebond-server-1
docker compose --env-file deploy.env logs --tail 12
printf 'HOST_WIREGUARD\n'
wg show interfaces
printf 'UNCHANGED_EXISTING_CONTAINERS\n'
docker ps --format '{{.Names}}' | grep -v '^gamebond-server-1$' | sort > existing-containers-after.txt
sort existing-containers-before.txt > existing-containers-before-sorted.txt
diff existing-containers-before-sorted.txt existing-containers-after.txt
printf 'NAMESPACE\n'
docker exec gamebond-server-1 sh -c 'ip -brief address; ip route; nft list table ip gamebond; ss -uln'
printf 'DISK\n'
df -h /var/lib/docker
if docker container inspect gamebond-smoke >/dev/null 2>&1; then
    echo 'gamebond-smoke container already exists; refusing reuse' >&2
    exit 1
fi
python3 - <<'PY'
import json, secrets
from pathlib import Path
config = json.loads(Path('configs/local-server.json').read_text())
config['session'] = secrets.token_hex(16)
Path('configs/smoke-server.json').write_text(json.dumps(config))
Path('secrets/smoke.key').write_bytes(secrets.token_bytes(32))
PY
smoke_started=0
cleanup() {
    if [ "$smoke_started" = 1 ]; then docker rm -f gamebond-smoke >/dev/null; fi
    rm -f "$release/configs/smoke-server.json" "$release/secrets/smoke.key"
}
trap cleanup EXIT
docker run -d --name gamebond-smoke --label gamebond.role=smoke \
    --network gamebond_tunnel --cap-drop ALL --cap-add NET_ADMIN \
    --device /dev/net/tun:/dev/net/tun:rw --sysctl net.ipv4.ip_forward=1 \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --security-opt no-new-privileges:true \
    --memory 256m --pids-limit 64 \
    --mount type=bind,src="$release/configs/smoke-server.json",dst=/run/config/server.json,readonly \
    --mount type=bind,src="$release/secrets/smoke.key",dst=/run/secrets/gamebond.key,readonly \
    gamebond:0.1.0
smoke_started=1
attempt=0
until docker exec gamebond-smoke test -f /tmp/gamebond-ready; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 20 ]; then docker logs gamebond-smoke; exit 1; fi
    sleep 1
done
docker exec -i gamebond-smoke python - <<'PY'
import json
from pathlib import Path
config = json.loads(Path('/run/config/server.json').read_text())
config.update(role='client', bind=[['127.0.0.1',0],['127.0.0.1',0]], peer=['127.0.0.1',4433])
Path('/tmp/client.json').write_text(json.dumps(config))
PY
# The probe source is appended here by assemble-verify.py and runs ONLY inside
# the isolated smoke container, with its own fresh key/session.
docker exec -i gamebond-smoke python - /tmp/client.json --key /run/secrets/gamebond.key <<'GAMEBOND_PROBE'
