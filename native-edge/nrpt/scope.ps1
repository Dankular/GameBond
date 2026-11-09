
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$state = $request.state
function Save-State {
    $record = @{version=1; kind='GameBond-DNS'; owner=$request.owner; state=$state;
        worker=@{pid=$PID; created=[string]([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc())}}
    $temporary = "$($request.journal_path).tmp-$PID"
    [IO.File]::WriteAllText($temporary, ($record | ConvertTo-Json -Depth 12 -Compress), [Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($request.journal_path)) { [IO.File]::Replace($temporary, $request.journal_path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $request.journal_path) }
}
function Exact-Namespace($actual, $expected) {
    $items = @($actual)
    return ($items.Count -eq 1 -and ([string]$items[0]).TrimEnd('.') -ieq $expected)
}
function Exact-Server($actual, $expected) {
    $items = @(([string]::Join(';', @($actual))) -split '[;,\s]+' | Where-Object { $_ })
    return ($items.Count -eq 1 -and $items[0] -eq $expected)
}
function Owned-Rule($rule, $planned) {
    return (($null -eq $planned.guid -or [string]$rule.Name -ieq $planned.guid) -and
        [string]$rule.DisplayName -ceq $planned.marker -and [string]$rule.Comment -ceq $planned.marker -and
        (Exact-Namespace $rule.Namespace $planned.namespace) -and (Exact-Server $rule.NameServers $state.resolver_ip))
}
function Remove-Owned {
    $failures = [Collections.Generic.List[string]]::new()
    try { $actual = @(Get-DnsClientNrptRule -ErrorAction Stop) }
    catch { $failures.Add($_.Exception.Message); return @($failures.ToArray()) }
    foreach ($planned in @($state.rules)) {
        $candidates = @($actual | Where-Object {
            ($planned.guid -and [string]$_.Name -ieq $planned.guid) -or [string]$_.DisplayName -ceq $planned.marker
        })
        foreach ($rule in $candidates) {
            if (-not (Owned-Rule $rule $planned)) {
                $failures.Add("Owned DNS rule fields changed: $($planned.marker)"); continue
            }
            try {
                Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
                $planned.verified=$false
                Save-State
            } catch { $failures.Add($_.Exception.Message) }
        }
    }
    return @($failures.ToArray())
}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'DNS scope requires administrator' }
    Save-State
    switch ($request.phase) {
        'activate' {
            $existing = @(Get-DnsClientNrptRule -ErrorAction Stop)
            foreach ($planned in @($state.rules)) {
                if ($existing | Where-Object {
                    @($_.Namespace | Where-Object { ([string]$_).TrimEnd('.') -ieq $planned.namespace }).Count -gt 0
                }) {
                    throw "Existing exact DNS namespace conflicts: $($planned.namespace)"
                }
                $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
                if ($effective | Where-Object { Exact-Namespace $_.Namespace $planned.namespace }) {
                    throw "Existing effective exact DNS namespace conflicts: $($planned.namespace)"
                }
            }
            foreach ($planned in @($state.rules)) {
                # The random marker is durable even if Add succeeds and the
                # process dies before its returned GUID can be saved.
                Save-State
                $created = @(Add-DnsClientNrptRule -Namespace $planned.namespace -NameServers $state.resolver_ip `
                    -DisplayName $planned.marker -Comment $planned.marker -PassThru -ErrorAction Stop)
                if ($created.Count -ne 1 -or -not $created[0].Name) { throw 'NRPT Add returned no unique rule identity' }
                $planned.guid=[string]$created[0].Name
                Save-State
                $readback = @(Get-DnsClientNrptRule -Name $planned.guid -ErrorAction Stop)
                if ($readback.Count -ne 1 -or -not (Owned-Rule $readback[0] $planned)) { throw 'Owned NRPT readback mismatch' }
                $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object {
                    Exact-Namespace $_.Namespace $planned.namespace
                })
                $matching = @($effective | Where-Object {
                    (Exact-Namespace $_.Namespace $planned.namespace) -and (Exact-Server $_.NameServers $state.resolver_ip)
                })
                if ($effective.Count -ne 1 -or $matching.Count -ne 1) { throw 'Effective NRPT server readback mismatch' }
                $planned.verified=$true
                Save-State
            }
        }
        'close' {
            $failures = @(Remove-Owned)
            if ($failures.Count) { throw ($failures -join '; ') }
        }
        default { throw 'Unknown DNS scope operation' }
    }
    @{ok=$true; state=$state} | ConvertTo-Json -Depth 12 -Compress
} catch {
    $message=$_.Exception.Message
    $rollback=@()
    if ($request.phase -eq 'activate') { $rollback=@(Remove-Owned) }
    try { Save-State } catch { $rollback += $_.Exception.Message }
    @{ok=$false; state=$state; error=$message; rollback_errors=$rollback} | ConvertTo-Json -Depth 12 -Compress
    exit 1
}
