set -e
T(){ echo "[+${SECONDS}s] $1"; }; SECONDS=0
cd "D:/Dev Proj/Speedify"; export GOFLAGS=-buildvcs=false
K="C:/Users/sysadmin/Desktop/privkey.ppk"; HK="SHA256:aEUdaCw8C09l+TUWYKqOgf05ty6ojqKueAZ65lK3UwI"; H=root@138.199.201.16
# The widget is a separate exe with its own embedded copy of the GUI: always rebuild it with the client.
(cd native-edge && go build -ldflags "-H=windowsgui" -o ../build/gamebond-widget.new.exe ./cmd/tray) & WB=$!
(cd native-edge && go build -o ../build/gamebond-native-client.new.exe ./cmd/client && go build -o ../build/gamebond-desktopctl.new.exe ./cmd/desktopctl) & CB=$!
(cd native-edge && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o ../build/gamebond-native-edge-linux ./cmd/edge)
wait $WB $CB
T 'go build done'
# Server: skip upload, image build and container recreate when the binary is unchanged.
SHA=$(sha256sum build/gamebond-native-edge-linux | cut -d' ' -f1)
if [ "$(cat build/.server-sha 2>/dev/null)" = "$SHA" ]; then SERVER=skip; else SERVER=deploy; fi
if [ $SERVER = deploy ]; then
  # The server image is built by GitHub Actions from the pushed commit; nothing is uploaded.
  git -c safe.directory='*' diff --quiet HEAD -- native-edge Dockerfile tools compose.yaml || { echo "uncommitted server changes: commit first, the server runs the pushed commit"; exit 1; }
  git -c safe.directory='*' push -q
  COMMIT=$(git -c safe.directory='*' rev-parse HEAD); IMG=ghcr.io/dankular/gamebond-native:$COMMIT
  mkdir -p .runtime; : > .runtime/deploy-pending
  (
    until [ "$(gh run list --workflow server-image.yml --commit $COMMIT --json status,conclusion -q '.[0].status+" "+.[0].conclusion' 2>/dev/null)" = "completed success" ]; do
      [ "$(gh run list --workflow server-image.yml --commit $COMMIT --json conclusion -q '.[0].conclusion' 2>/dev/null)" = failure ] && { echo "CI BUILD FAILED" > .runtime/deploy-server.out; rm -f .runtime/deploy-pending; exit 1; }
      sleep 1
    done
    echo "[+${SECONDS}s] image built"
    timeout 110 plink -batch -T -i $K -hostkey $HK $H "set -eu
R=/opt/gamebond/releases/native-live
docker pull -q $IMG >/dev/null
cd \$R && (grep -q '^GAMEBOND_IMAGE=' deploy.env && sed -i 's|^GAMEBOND_IMAGE=.*|GAMEBOND_IMAGE=$IMG|' deploy.env || echo 'GAMEBOND_IMAGE=$IMG' >> deploy.env)
docker compose --env-file deploy.env up -d --no-build --force-recreate >/dev/null 2>&1
n=0; until docker exec gamebond-native-1 sh -c 'test -e /tmp/gamebond-ready && test -d /sys/class/net/gamebond0 && kill -0 \$(cat /tmp/gamebond.pid)' 2>/dev/null; do n=\$((n+1)); [ \$n -ge 300 ] && { echo FAILED; exit 1; }; sleep 0.1; done; echo DEPLOYED" 2>&1 | tail -1 | tee .runtime/deploy-server.out
    grep -q DEPLOYED .runtime/deploy-server.out && echo "$SHA" > build/.server-sha
    rm -f .runtime/deploy-pending
  ) & SB=$!
else
  echo "server binary unchanged: skipping upload, image build and recreate"
fi
# Client swap runs while the server restarts; its connect waits for deploy-pending to clear.
powershell -NoProfile -File tools/elevate.ps1 -File "$(cygpath -w tools/redeploy-client.ps1)" | tail -1
T 'client redeployed'
[ $SERVER = deploy ] && { wait $SB || true; grep -q DEPLOYED .runtime/deploy-server.out || { echo "SERVER DEPLOY FAILED"; exit 1; }; T 'server ready'; }
powershell -NoProfile -Command "Get-Process gamebond-widget -ErrorAction SilentlyContinue | Stop-Process -Force; Move-Item -Force build/gamebond-widget.new.exe build/gamebond-widget.exe; Start-Process -FilePath ./start-widget.cmd -WindowStyle Hidden"
T 'widget done'
echo WIDGET-RELAUNCHED
