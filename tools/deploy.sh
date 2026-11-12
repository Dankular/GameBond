set -e
T(){ echo "[+${SECONDS}s] $1"; }; SECONDS=0
cd "D:/Dev Proj/Speedify"; export GOFLAGS=-buildvcs=false
K="C:/Users/sysadmin/Desktop/privkey.ppk"; HK="SHA256:aEUdaCw8C09l+TUWYKqOgf05ty6ojqKueAZ65lK3UwI"; H=root@138.199.201.16
# The widget is a separate exe with its own embedded copy of the GUI: always rebuild it with the client.
(cd native-edge && go build -ldflags "-H=windowsgui" -o ../build/gamebond-widget.new.exe ./cmd/tray) & WB=$!
COMMIT=$(git -c safe.directory='*' rev-parse HEAD); git -c safe.directory='*' diff --quiet HEAD -- native-edge || COMMIT="$COMMIT-dirty"
LD="-X gamebond.local/nativeedge/buildinfo.Commit=$COMMIT"
(cd native-edge && go build -ldflags "$LD" -o ../build/gamebond-native-client.new.exe ./cmd/client && go build -o ../build/gamebond-desktopctl.new.exe ./cmd/desktopctl) & CB=$!
(cd native-edge && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o ../build/gamebond-native-edge-linux ./cmd/edge)
wait $WB $CB
T 'go build done'
# Server: skip upload, image build and container recreate when the binary is unchanged.
SERVER=deploy
if [ $SERVER = deploy ]; then
  # The server image is built by GitHub Actions from the pushed commit; nothing is uploaded.
  git -c safe.directory='*' diff --quiet HEAD -- native-edge Dockerfile tools compose.yaml || { echo "uncommitted server changes: commit first, the server runs the pushed commit"; exit 1; }
  git -c safe.directory='*' push -q
  COMMIT=$(git -c safe.directory='*' rev-parse HEAD); IMG=ghcr.io/dankular/gamebond-native:$COMMIT
  mkdir -p .runtime; : > .runtime/deploy-pending
  (
    until [ "$(gh run list -R Dankular/GameBond --workflow server-image.yml --commit $COMMIT --json status,conclusion -q '.[0].status+" "+.[0].conclusion' 2>/dev/null)" = "completed success" ]; do
      [ "$(gh run list -R Dankular/GameBond --workflow server-image.yml --commit $COMMIT --json conclusion -q '.[0].conclusion' 2>/dev/null)" = failure ] && { echo "CI BUILD FAILED" > .runtime/deploy-server.out; rm -f .runtime/deploy-pending; exit 1; }
      sleep 1
    done
    echo "[+${SECONDS}s] image built"
    # The server-side probe owns the update (flock, readiness wait, rollback); here it is just told which commit.
    timeout 110 plink -batch -T -i $K -hostkey $HK $H "/usr/local/bin/gamebond-probe update $COMMIT >/dev/null 2>&1; grep -q '^GAMEBOND_IMAGE=$IMG\$' /opt/gamebond/releases/native-live/deploy.env && docker exec gamebond-native-1 sh -c 'test -e /tmp/gamebond-ready && test -d /sys/class/net/gamebond0' && echo DEPLOYED" 2>&1 | tail -1 | tee .runtime/deploy-server.out
    # The recreate can drop this SSH session; re-check readiness on a fresh one before calling it failed.
    grep -q DEPLOYED .runtime/deploy-server.out || for _ in 1 2 3 4 5 6 7 8; do
      timeout 20 plink -batch -T -i $K -hostkey $HK $H "docker exec gamebond-native-1 sh -c 'test -e /tmp/gamebond-ready && test -d /sys/class/net/gamebond0' && echo DEPLOYED" 2>/dev/null | tail -1 > .runtime/deploy-server.out
      grep -q DEPLOYED .runtime/deploy-server.out && break; sleep 1
    done
    rm -f .runtime/deploy-pending
  ) & SB=$!
else
  echo "server binary unchanged: skipping upload, image build and recreate"
fi
# Client swap runs while the server restarts; its connect waits for deploy-pending to clear.
# Unchanged binaries are not restarted: the tunnel stays up and the step costs nothing.
same(){ [ -f "$2" ] && [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }
if same build/gamebond-native-client.new.exe build/gamebond-native-client.exe && same build/gamebond-desktopctl.new.exe build/gamebond-desktopctl.exe; then
  T 'client unchanged: not restarted'
else
  powershell -NoProfile -File tools/elevate.ps1 -File "$(cygpath -w tools/redeploy-client.ps1)" | tail -1
  T 'client redeployed'
fi
[ $SERVER = deploy ] && { wait $SB || true; grep -q DEPLOYED .runtime/deploy-server.out || { echo "SERVER DEPLOY FAILED"; exit 1; }; T 'server ready'; }
if same build/gamebond-widget.new.exe build/gamebond-widget.exe; then rm -f build/gamebond-widget.new.exe; T 'widget unchanged: not relaunched'; else
powershell -NoProfile -Command "Get-Process gamebond-widget -ErrorAction SilentlyContinue | Stop-Process -Force; while (Get-Process gamebond-widget -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 20 }; Move-Item -Force build/gamebond-widget.new.exe build/gamebond-widget.exe; Start-Process -FilePath ./start-widget.cmd -WindowStyle Hidden"
T 'widget done'
fi
echo WIDGET-RELAUNCHED
