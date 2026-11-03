@echo off
setlocal
cd /d "%~dp0"
python -c "import ctypes,sys; sys.exit(0 if ctypes.windll.shell32.IsUserAnAdmin() else 1)"
if errorlevel 1 (
  echo Right-click cleanup-old-client.cmd and choose Run as administrator.
  pause
  exit /b 1
)
echo Removing the two recorded legacy endpoint routes and strictly identified old CoD QoS policies.
python -m gamebond.windows_network cleanup-legacy
if errorlevel 1 (
  pause
  exit /b 1
)
python -m gamebond.windows_network cleanup
if errorlevel 1 pause
