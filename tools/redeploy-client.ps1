# Full client restart: client, netstack and ProxiFyre are all replaced. The tunnel drops for a few seconds.
Set-Location 'D:\Dev Proj\Speedify'
.\build\gamebond-desktopctl.exe stop
Start-Sleep 4
Get-Process gamebond-native-client,gamebond-netstack-attribution,ProxiFyre -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Copy-Item -Force build\gamebond-native-client.exe build\gamebond-native-client.prev.exe -ErrorAction SilentlyContinue
Copy-Item -Force build\gamebond-native-client.new.exe build\gamebond-native-client.exe
Copy-Item -Force build\gamebond-desktopctl.new.exe build\gamebond-desktopctl.exe
.\build\gamebond-desktopctl.exe ensure
Start-Sleep 3
.\build\gamebond-desktopctl.exe connect
