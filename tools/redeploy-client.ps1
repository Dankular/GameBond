# Full client restart: client, netstack and ProxiFyre are replaced. Every wait polls the real
# condition instead of sleeping.
Set-Location 'D:\Dev Proj\Speedify'
$t0 = [DateTime]::UtcNow
function Lap($n) { Write-Output ('  {0,6:N0} ms {1}' -f ([DateTime]::UtcNow - $t0).TotalMilliseconds, $n) }
function WaitFor($cond, $ms) { $end = [DateTime]::UtcNow.AddMilliseconds($ms); while (-not (& $cond) -and [DateTime]::UtcNow -lt $end) { Start-Sleep -Milliseconds 10 } }
.\build\gamebond-desktopctl.exe stop | Out-Null
Lap 'stop returned'
$names = 'gamebond-native-client', 'gamebond-netstack-attribution', 'ProxiFyre'
# A graceful stop leaves ProxiFyre running until it is killed; waiting for it cost 3 s every time.
Get-Process $names -ErrorAction SilentlyContinue | Stop-Process -Force
WaitFor { -not (Get-Process $names -ErrorAction SilentlyContinue) } 2000
Lap 'processes exited'
Copy-Item -Force build\gamebond-native-client.exe build\gamebond-native-client.prev.exe -ErrorAction SilentlyContinue
Copy-Item -Force build\gamebond-native-client.new.exe build\gamebond-native-client.exe
Copy-Item -Force build\gamebond-desktopctl.new.exe build\gamebond-desktopctl.exe
if (Test-Path build\gamebond-netstack-attribution.new.exe) {
  Copy-Item -Force build\gamebond-netstack-attribution.exe build\gamebond-netstack-attribution.prev.exe -ErrorAction SilentlyContinue
  Copy-Item -Force build\gamebond-netstack-attribution.new.exe build\gamebond-netstack-attribution.exe
}
Lap 'binaries swapped'
.\build\gamebond-desktopctl.exe ensure | Out-Null
Lap 'ensure returned'
WaitFor { (.\build\gamebond-desktopctl.exe status) -match '"ok":true' } 5000
Lap 'supervisor status ok'
.\build\gamebond-desktopctl.exe connect | Out-Null
Lap 'connect returned'
