#!/bin/sh
set -eu
cd /opt/gamebond/releases/5fbd6b092d1dfc85849a92eb4a286092
python3 - <<'PY'
import json
from pathlib import Path
path = Path('configs/local-server.json')
config = json.loads(path.read_text())
config['session'] = '5c8f636cdd824368285a04401e19e4e6'
path.write_text(json.dumps(config, indent=2) + '\n')
PY
docker compose --env-file deploy.env restart server
attempt=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' gamebond-server-1)" = healthy ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 30 ]; then docker compose --env-file deploy.env logs --tail 15; exit 1; fi
    sleep 1
done
docker inspect --format '{{.State.Status}} {{.State.Health.Status}}' gamebond-server-1
docker compose --env-file deploy.env logs --tail 3
wg show interfaces
printf 'FRESH_GAMEBOND_SESSION_READY\n'
