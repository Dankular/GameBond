Set-Location 'D:\Dev Proj\Speedify'
.\build\gamebond-desktopctl.exe stop
Get-Process ProxiFyre -ErrorAction SilentlyContinue | Stop-Process -Force
