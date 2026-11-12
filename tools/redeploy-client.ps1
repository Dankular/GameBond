# Full client restart: client, netstack and ProxiFyre are replaced. Every wait polls the real
# condition instead of sleeping. If .runtime\deploy-pending exists (deploy.sh, server restarting) the
# final connect waits until it is removed, so the client swap overlaps the server restart.
Set-Location 'D:\Dev Proj\Speedify'
function WaitFor($cond, $ms) { $end = [DateTime]::UtcNow.AddMilliseconds($ms); while (-not (& $cond) -and [DateTime]::UtcNow -lt $end) { Start-Sleep -Milliseconds 20 } }
.\build\gamebond-desktopctl.exe stop | Out-Null
$names = 'gamebond-native-client','gamebond-netstack-attribution','ProxiFyre'
WaitFor { -not (Get-Process $names -ErrorAction SilentlyContinue) } 3000
Get-Process $names -ErrorAction SilentlyContinue | Stop-Process -Force
WaitFor { -not (Get-Process $names -ErrorAction SilentlyContinue) } 3000
Copy-Item -Force build\gamebond-native-client.exe build\gamebond-native-client.prev.exe -ErrorAction SilentlyContinue
Copy-Item -Force build\gamebond-native-client.new.exe build\gamebond-native-client.exe
Copy-Item -Force build\gamebond-desktopctl.new.exe build\gamebond-desktopctl.exe
.\build\gamebond-desktopctl.exe ensure | Out-Null
WaitFor { (.\build\gamebond-desktopctl.exe status) -match '"ok":true' } 5000
WaitFor { -not (Test-Path .runtime\deploy-pending) } 60000
.\build\gamebond-desktopctl.exe connect
