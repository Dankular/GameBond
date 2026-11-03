[CmdletBinding()]
param(
    [string]$Profile = (Join-Path $PSScriptRoot '..\configs\cod-profile.json'),
    [switch]$Apply,
    [switch]$Undo
)
$ErrorActionPreference = 'Stop'
if ($Apply -and $Undo) { throw 'Choose Apply or Undo' }
$config = Get-Content -LiteralPath $Profile -Raw | ConvertFrom-Json
if ($config.dscp -lt 0 -or $config.dscp -gt 63) { throw 'DSCP must be 0..63' }
$entries = @($config.executables | ForEach-Object {
    [pscustomobject]@{ Path=$_; Name=('GameBond-CoD-' + [System.IO.Path]::GetFileName($_)) }
})
if (@($entries.Name | Select-Object -Unique).Count -ne $entries.Count) { throw 'Duplicate executable policy names' }
if (-not $Apply -and -not $Undo) {
    $entries | Select-Object Name,Path,@{Name='Protocol';Expression={'UDP'}},@{Name='DSCP';Expression={$config.dscp}}
    Write-Output 'Review only. Use -Apply in an elevated terminal to create these process UDP QoS policies; -Undo removes only these named policies.'
    return
}
$policies = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
if ($Undo) {
    foreach ($entry in $entries) {
        if ($policies | Where-Object Name -eq $entry.Name) {
            Remove-NetQosPolicy -Name $entry.Name -PolicyStore ActiveStore -Confirm:$false
        }
    }
    return
}
foreach ($entry in $entries) {
    if (-not [System.IO.Path]::IsPathRooted($entry.Path) -or -not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) { throw "Game executable missing: $($entry.Path)" }
    if ($policies | Where-Object Name -eq $entry.Name) { throw "Policy already exists: $($entry.Name)" }
}
$created = [System.Collections.Generic.List[string]]::new()
try {
    foreach ($entry in $entries) {
        New-NetQosPolicy -Name $entry.Name -AppPathNameMatchCondition $entry.Path -IPProtocolMatchCondition UDP -DSCPAction $config.dscp -PolicyStore ActiveStore
        $created.Add($entry.Name)
    }
} catch {
    foreach ($name in $created) { Remove-NetQosPolicy -Name $name -PolicyStore ActiveStore -Confirm:$false -ErrorAction Continue }
    throw
}
