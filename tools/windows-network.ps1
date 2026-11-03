[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9.]+$')][string]$ServerIPv4,
    [Parameter(Mandatory)][int]$StarlinkIndex,
    [Parameter(Mandatory)][string]$StarlinkGateway,
    [Parameter(Mandatory)][int]$FiveGIndex,
    [Parameter(Mandatory)][string]$FiveGGateway,
    [string]$TunName = 'GameBond',
    [string]$GameExe,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
# Review commands by default. Run only after GameBond has created its adapter.
foreach ($value in @($ServerIPv4, $StarlinkGateway, $FiveGGateway)) {
    $parsed = [System.Net.IPAddress]::Parse($value)
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'IPv4 required' }
}
if ($StarlinkIndex -le 0 -or $FiveGIndex -le 0 -or $StarlinkIndex -eq $FiveGIndex) {
    throw 'Two distinct physical interface indices are required'
}
$actions = [System.Collections.Generic.List[scriptblock]]::new()
$actions.Add({ New-NetRoute -DestinationPrefix "$ServerIPv4/32" -InterfaceIndex $StarlinkIndex -NextHop $StarlinkGateway -PolicyStore ActiveStore })
$actions.Add({ New-NetRoute -DestinationPrefix "$ServerIPv4/32" -InterfaceIndex $FiveGIndex -NextHop $FiveGGateway -PolicyStore ActiveStore })
$actions.Add({ New-NetIPAddress -InterfaceAlias $TunName -IPAddress '10.77.0.2' -PrefixLength 30 -AddressFamily IPv4 -PolicyStore ActiveStore })
$actions.Add({ Set-NetIPInterface -InterfaceAlias $TunName -AddressFamily IPv4 -NlMtuBytes 1280 })
$actions.Add({ New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias $TunName -NextHop '0.0.0.0' -PolicyStore ActiveStore })
$actions.Add({ New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias $TunName -NextHop '0.0.0.0' -PolicyStore ActiveStore })
if ($GameExe) {
    if (-not [System.IO.Path]::IsPathRooted($GameExe) -or -not (Test-Path -LiteralPath $GameExe -PathType Leaf)) { throw 'GameExe must be the actual absolute installed CoD executable path' }
    $actions.Add({ New-NetQosPolicy -Name 'GameBond-CoD' -AppPathNameMatchCondition $GameExe -IPProtocolMatchCondition UDP -DSCPAction 46 -PolicyStore ActiveStore })
}
if (-not $Apply) {
    Write-Output "Review: endpoint=$ServerIPv4, Starlink=$StarlinkIndex via $StarlinkGateway, 5G=$FiveGIndex via $FiveGGateway, TUN=$TunName, game=$GameExe"
    $actions | ForEach-Object { $_.ToString().Trim() }
    return
}
# Preflight all references and collisions before making changes.
$tun = Get-NetAdapter -Name $TunName -ErrorAction Stop
if (@($tun).Count -ne 1) { throw 'Exactly one GameBond adapter is required' }
# Enumerate once, then filter locally. A missing exact-match CIM query can emit
# an error; SilentlyContinue would also hide permission/provider failures.
$routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
$physical = @(Get-NetAdapter -Physical -ErrorAction Stop)
foreach ($index in @($StarlinkIndex, $FiveGIndex)) {
    $adapter = @($physical | Where-Object { $_.ifIndex -eq $index })
    if ($adapter.Count -ne 1 -or $adapter[0].Status -ne 'Up' -or $index -eq $tun.ifIndex) { throw 'Physical adapter must exist, be up and separate from TUN' }
    if ($routes | Where-Object { $_.DestinationPrefix -eq "$ServerIPv4/32" -and $_.InterfaceIndex -eq $index }) { throw 'Existing endpoint host route: review it manually before applying' }
}
if ($addresses | Where-Object { $_.IPAddress -eq '10.77.0.2' }) { throw 'GameBond address already exists on an interface' }
if ($routes | Where-Object { $_.InterfaceIndex -eq $tun.ifIndex -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }) { throw 'GameBond routes already exist' }
if ($GameExe) {
    $policies = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
    if ($policies | Where-Object { $_.Name -eq 'GameBond-CoD' }) { throw 'GameBond-CoD policy already exists' }
}
$created = [System.Collections.Generic.List[object]]::new()
$oldMtu = (Get-NetIPInterface -InterfaceAlias $TunName -AddressFamily IPv4).NlMtuBytes
$qosAdded = $false
try {
    foreach ($action in $actions) {
        $result = & $action
        foreach ($item in @($result)) {
            if ($item) { $created.Add($item) }
        }
        if ($action.ToString() -match 'New-NetQosPolicy') { $qosAdded = $true }
    }
    Write-Output 'Applied active-session routes. Stop GameBond to remove its adapter and tunnel routes.'
    Write-Output "After stopping, remove the two endpoint routes with: Get-NetRoute -DestinationPrefix '$ServerIPv4/32' -InterfaceIndex $StarlinkIndex,$FiveGIndex | Remove-NetRoute -Confirm:`$false"
    if ($qosAdded) { Write-Output "Remove-NetQosPolicy -Name 'GameBond-CoD' -PolicyStore ActiveStore -Confirm:`$false" }
} catch {
    # Roll back only objects returned by this invocation, in reverse order.
    for ($i = $created.Count - 1; $i -ge 0; $i--) {
        $item = $created[$i]
        if ($item.CimClass.CimClassName -eq 'MSFT_NetRoute') { $item | Remove-NetRoute -Confirm:$false -ErrorAction Continue }
        elseif ($item.CimClass.CimClassName -eq 'MSFT_NetIPAddress') { $item | Remove-NetIPAddress -Confirm:$false -ErrorAction Continue }
    }
    if ($qosAdded) { Remove-NetQosPolicy -Name 'GameBond-CoD' -PolicyStore ActiveStore -Confirm:$false -ErrorAction Continue }
    Set-NetIPInterface -InterfaceAlias $TunName -AddressFamily IPv4 -NlMtuBytes $oldMtu -ErrorAction Continue
    throw
}
