@echo off
cd /d "%~dp0"
if not exist "%~dp0build\gamebond-widget.exe" (
  echo Build the Go desktop widget first: cd native-edge ^&^& set GOFLAGS=-buildvcs=false ^&^& go build -ldflags "-H=windowsgui" -o ..\build\gamebond-widget.exe ./cmd/tray
  pause
  exit /b 1
)
start "GameBond" "%~dp0build\gamebond-widget.exe" -root "%~dp0."
