set -e
# Client deploy: build, swap the client and widget. The server is a separate repo
# (GameBond.Server); its CI builds the image and the probe on the VPS applies it.
T(){ echo "[+${SECONDS}s] $1"; }; SECONDS=0
cd "D:/Dev Proj/Speedify"; export GOFLAGS=-buildvcs=false
G="git -c safe.directory=*"
COMMIT=$($G rev-parse HEAD); $G diff --quiet HEAD -- native-edge || COMMIT="$COMMIT-dirty"
LD="-X github.com/Dankular/GameBond.Core/buildinfo.Commit=$COMMIT"
# The widget is a separate exe with its own embedded copy of the GUI: always rebuild it with the client.
(cd native-edge && go build -ldflags "-H=windowsgui" -o ../build/gamebond-widget.new.exe ./cmd/tray) & WB=$!
(cd native-edge && go build -ldflags "$LD" -o ../build/gamebond-native-client.new.exe ./cmd/client && go build -o ../build/gamebond-desktopctl.new.exe ./cmd/desktopctl) & CB=$!
wait $WB $CB
T 'go build done'
$G push -q 2>/dev/null || true
# Unchanged binaries are not restarted: the tunnel stays up and the step costs nothing.
same(){ [ -f "$2" ] && [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }
if same build/gamebond-native-client.new.exe build/gamebond-native-client.exe && same build/gamebond-desktopctl.new.exe build/gamebond-desktopctl.exe; then
  T 'client unchanged: not restarted'
else
  powershell -NoProfile -File tools/elevate.ps1 -File "$(cygpath -w tools/redeploy-client.ps1)" | tail -1
  T 'client redeployed'
fi
if same build/gamebond-widget.new.exe build/gamebond-widget.exe; then rm -f build/gamebond-widget.new.exe; T 'widget unchanged: not relaunched'; else
# A running exe can be renamed on Windows, so swap the files first and replace the process after: no race.
powershell -NoProfile -Command "Remove-Item -Force build/gamebond-widget.old.exe -ErrorAction SilentlyContinue; if (Test-Path build/gamebond-widget.exe) { Move-Item -Force build/gamebond-widget.exe build/gamebond-widget.old.exe }; Move-Item -Force build/gamebond-widget.new.exe build/gamebond-widget.exe; Get-Process gamebond-widget -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Process -FilePath ./start-widget.cmd -WindowStyle Hidden"
T 'widget done'
fi
echo WIDGET-RELAUNCHED
