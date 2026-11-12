set -e
cd "D:/Dev Proj/Speedify"; export GOFLAGS=-buildvcs=false
S=C:/Users/sysadmin/AppData/Local/Temp/claude/dbcad5a4a359a75f/4914eae1-ae11-4af0-ae44-bad0f5cebc37/scratchpad
(cd native-edge && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../build/gamebond-native-edge-linux ./cmd/edge && go build -o ../build/gamebond-native-client.new.exe ./cmd/client && go build -o ../build/gamebond-desktopctl.new.exe ./cmd/desktopctl)
gzip -c build/gamebond-native-edge-linux > "$TEMP/ne.gz"
powershell -NoProfile -File tools/elevate.ps1 -File "$(cygpath -w tools/stop-client.ps1)" | tail -1
K="C:/Users/sysadmin/Desktop/privkey.ppk"; HK="SHA256:aEUdaCw8C09l+TUWYKqOgf05ty6ojqKueAZ65lK3UwI"; H=root@138.199.201.16
timeout 100 pscp -batch -i $K -hostkey $HK "$TEMP/ne.gz" $H:/tmp/ne.gz >/dev/null 2>&1
timeout 110 plink -batch -T -i $K -hostkey $HK $H 'set -eu
S=/opt/gamebond/staging-native; R=/opt/gamebond/releases/native-live
gunzip -c /tmp/ne.gz > $S/gamebond-native-edge && chmod 755 $S/gamebond-native-edge && rm /tmp/ne.gz
(cd $S && docker build -q -t gamebond:native-live . >/dev/null)
cd $R && docker compose --env-file deploy.env up -d --no-build --force-recreate 2>&1 | tail -1
n=0; until [ "$(docker inspect --format "{{.State.Health.Status}}" gamebond-native-1)" = healthy ]; do n=$((n+1)); [ $n -ge 40 ] && { echo FAILED; exit 1; }; sleep 2; done; echo DEPLOYED' 2>&1 | tail -1
powershell -NoProfile -File tools/elevate.ps1 -File "$(cygpath -w tools/redeploy-client.ps1)" | tail -1
# The widget is a separate exe with its own embedded copy of the GUI: always rebuild and relaunch it with the client.
(cd native-edge && go build -ldflags "-H=windowsgui" -o ../build/gamebond-widget.new.exe ./cmd/tray)
powershell -NoProfile -Command "Get-Process gamebond-widget -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1; Move-Item -Force build/gamebond-widget.new.exe build/gamebond-widget.exe; Start-Process -FilePath ./start-widget.cmd -WindowStyle Hidden"
echo WIDGET-RELAUNCHED
