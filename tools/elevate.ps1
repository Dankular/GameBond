<#
.SYNOPSIS
  Run a command elevated (UAC prompt) and stream its output back to the caller.

.EXAMPLE
  .\elevate.ps1 'Copy-Item C:\Windows\Minidump\*.dmp D:\dumps\'
  .\elevate.ps1 -File .\some-admin-task.ps1
  .\elevate.ps1 -Command 'Get-Item C:\Windows\MEMORY.DMP' -TimeoutSec 60

  Exit code is the elevated command's exit code (1 on error, 125 if UAC was declined, 124 on timeout).
  Output is captured to a temp file and printed after the elevated window closes.
#>
[CmdletBinding(DefaultParameterSetName = 'Cmd')]
param(
    [Parameter(ParameterSetName = 'Cmd', Position = 0, Mandatory)][string]$Command,
    [Parameter(ParameterSetName = 'File', Mandatory)][string]$File,
    [string]$WorkingDirectory = (Get-Location).Path,
    [int]$TimeoutSec = 300,
    [switch]$KeepWindow
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')

if ($PSCmdlet.ParameterSetName -eq 'File') {
    $File = (Resolve-Path $File).Path
    $Command = "& '$($File -replace "'", "''")'"
}

# Already elevated: just run it.
if ($isAdmin) {
    Set-Location $WorkingDirectory
    Invoke-Expression $Command
    exit $LASTEXITCODE
}

$tmp = Join-Path $env:TEMP ("elevate_{0}.log" -f [guid]::NewGuid().ToString('N'))
$wd  = $WorkingDirectory -replace "'", "''"
$tmpQ = $tmp -replace "'", "''"

# Wrapper runs in the elevated process; everything (all streams) goes to the log file.
$wrapper = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$wd'
`$code = 0
try {
    & {
        $Command
    } *>&1 | Out-File -FilePath '$tmpQ' -Encoding utf8
    if (`$LASTEXITCODE) { `$code = `$LASTEXITCODE }
    elseif (-not `$?)   { `$code = 1 }
} catch {
    `$_ | Out-File -FilePath '$tmpQ' -Encoding utf8 -Append
    `$code = 1
}
Add-Content -Path '$tmpQ' -Value "__EXIT__`$code" -Encoding utf8
"@

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapper))
$args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
if ($KeepWindow) { $args = @('-NoExit') + $args }

$pwsh = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $pwsh) { $pwsh = (Get-Command powershell.exe).Source }

try {
    $p = Start-Process -FilePath $pwsh -ArgumentList $args -Verb RunAs -WindowStyle Hidden -PassThru
} catch {
    Write-Error "Elevation was declined or failed: $($_.Exception.Message)"
    exit 125
}

if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    Write-Error "Timed out after ${TimeoutSec}s waiting for elevated process (PID $($p.Id))."
    exit 124
}

$exit = 1
if (Test-Path $tmp) {
    $lines = Get-Content $tmp
    foreach ($l in $lines) {
        if ($l -match '^__EXIT__(\d+)$') { $exit = [int]$Matches[1] } else { $l }
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
} else {
    Write-Warning 'Elevated process produced no output.'
}
exit $exit
