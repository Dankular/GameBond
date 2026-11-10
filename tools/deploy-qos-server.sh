#!/bin/sh
# Deploys the QoS server build (delay_control, failover_replay, loss_tracking)
# on top of the running image. Run from the repo root on a machine with plink/pscp:
#   sh tools/deploy-qos-server.sh
# Rolls back to the previous image and config if the container is not healthy.
set -eu
HOST=root@195.154.119.136
KEY=${KEY:-$HOME/Desktop/privkey.ppk}
REL=/opt/gamebond/releases/native-a8492d9c4707
TAG=native-qos$(date +%H%M)
(cd native-edge && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "-s -w" -o ../build/gamebond-native-edge-linux ./cmd/edge)
mkdir -p build/stg && cp build/gamebond-native-edge-linux build/stg/gamebond-native-edge
OLD=$(plink -batch -T -i "$KEY" $HOST "sed -n 's/^GAMEBOND_IMAGE=//p' $REL/deploy.env")
printf 'FROM %s\nCOPY --chmod=0755 gamebond-native-edge /usr/local/bin/gamebond-native-edge\n' "$OLD" > build/stg/Dockerfile
pscp -batch -i "$KEY" build/stg/gamebond-native-edge build/stg/Dockerfile $HOST:/tmp/
plink -batch -T -i "$KEY" $HOST "set -eu
mkdir -p /opt/gamebond/staging-$TAG && mv /tmp/gamebond-native-edge /tmp/Dockerfile /opt/gamebond/staging-$TAG/
(cd /opt/gamebond/staging-$TAG && docker build -q -t gamebond:$TAG .)
cd $REL
cp configs/local-server.json configs/local-server.json.pre-qos
cp deploy.env deploy.env.pre-qos
python3 - <<'PY'
import json
p='configs/local-server.json'
c=json.load(open(p))
c.update({'failover_replay':True,'loss_tracking':True,'delay_control':True})
if '$PHM': c['priority_host_max_packet']=int('$PHM')
json.dump(c,open(p,'w'),indent=2)
PY
sed -i 's|^GAMEBOND_IMAGE=.*|GAMEBOND_IMAGE=gamebond:$TAG|' deploy.env
docker compose --env-file deploy.env up -d --no-build
n=0; until [ \"\$(docker inspect --format '{{.State.Health.Status}}' gamebond-server-1)\" = healthy ]; do
  n=\$((n+1)); if [ \$n -ge 45 ]; then
    cp configs/local-server.json.pre-qos configs/local-server.json; cp deploy.env.pre-qos deploy.env
    docker compose --env-file deploy.env up -d --no-build; echo ROLLED BACK; exit 1; fi; sleep 2; done
echo DEPLOYED gamebond:$TAG"
