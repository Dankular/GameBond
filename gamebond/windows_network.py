"""Explicit, transactional Windows IPv4 setup for the multipath client.

The app creates its own Wintun adapter first. prepare() pins endpoint routes and
addresses that adapter; the caller checks all selected authenticated paths before
activate() adds full IPv4 routes and optional executable UDP DSCP policies. No
PowerShell execution-policy settings are changed. IPv6 is outside this helper.
"""
from __future__ import annotations
from .link_limits import MIN_LINKS,MAX_LINKS

import ctypes
import ipaddress
import json
import ntpath
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


class WindowsNetworkError(RuntimeError):
    pass


def _require_windows_admin():
    if sys.platform != "win32":
        raise WindowsNetworkError("--configure requires Windows")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise WindowsNetworkError("--configure requires Run as administrator")


# Fixed code: all configuration and state enter through JSON stdin, never code
# interpolation. ActiveStore objects have no free-form owner field; a random
# per-run route metric and QoS names distinguish this run's planned objects.
# Cleanup additionally matches interface, prefix, next hop and protocol, and
# never flushes interfaces, routing tables, other QoS policies or IPv6.
_POWERSHELL = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$state = $request.state

function Save-State {
    if (-not $request.journal_path -or $null -eq $state) { return }
    $record = @{version=1; owner=$request.owner; state=$state;
        worker=@{pid=$PID; created=[string]([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc())}}
    $temporary = "$($request.journal_path).tmp-$PID"
    [IO.File]::WriteAllText($temporary, ($record | ConvertTo-Json -Depth 20 -Compress), [Text.UTF8Encoding]::new($false))
    # Windows PowerShell 5.1 binds $null to an empty String for this .NET
    # overload. File.Replace then rejects the empty backup path. Preserve an
    # actual null String so replacement remains atomic without a backup file.
    if ([IO.File]::Exists($request.journal_path)) { [IO.File]::Replace($temporary, $request.journal_path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $request.journal_path) }
}

function All-Routes { @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop) }
function All-Addresses { @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop) }
function Owned-Route($route, $planned) {
    return ($route.InterfaceIndex -eq $planned.index -and
        $route.DestinationPrefix -eq $planned.prefix -and
        $route.NextHop -eq $planned.gateway -and
        $route.RouteMetric -eq $planned.metric -and
        [string]$route.Protocol -eq 'NetMgmt' -and
        (-not $planned.instance_id -or [string]$route.InstanceID -ceq $planned.instance_id))
}
function Check-Tun($s) {
    $matches = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        $_.ifIndex -eq $s.tun_index -and $_.Name -ceq $s.config.tun_name -and
        [string]$_.InterfaceGuid -ceq $s.tun_guid
    })
    if ($matches.Count -ne 1) { throw 'The owned GameBond adapter changed or disappeared' }
}
function Remove-Owned($s) {
    $failures = [System.Collections.Generic.List[string]]::new()
    # A deleted TUN already removes its own routes/address. Endpoint routes on
    # physical interfaces still need cleanup, so enumerate these independently.
    try {
        $routes = @(All-Routes)
        foreach ($planned in @($s.routes | Where-Object { $_.added })) {
            foreach ($route in @($routes | Where-Object { Owned-Route $_ $planned })) {
                try { $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop; $planned.added=$false; Save-State }
                catch { $failures.Add($_.Exception.Message) }
            }
        }
    } catch { $failures.Add($_.Exception.Message) }
    if (@($s.qos | Where-Object { $_.added }).Count -gt 0) {
        try {
            $policies = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
            foreach ($planned in @($s.qos | Where-Object { $_.added })) {
                foreach ($policy in @($policies | Where-Object { $_.Name -ieq $planned.name })) {
                    try { $policy | Remove-NetQosPolicy -Confirm:$false -ErrorAction Stop; $planned.added=$false; Save-State }
                    catch { $failures.Add($_.Exception.Message) }
                }
            }
        } catch { $failures.Add($_.Exception.Message) }
    }
    try {
        $tun = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            $_.ifIndex -eq $s.tun_index -and $_.Name -ceq $s.config.tun_name -and
            [string]$_.InterfaceGuid -ceq $s.tun_guid
        })
        if ($tun.Count -eq 1) {
            foreach ($address in @(All-Addresses | Where-Object {
                $s.address_added -and
                $_.InterfaceIndex -eq $s.tun_index -and
                $_.IPAddress -eq $s.config.client_tunnel_ip -and
                $_.PrefixLength -eq 30 -and [string]$_.PrefixOrigin -eq 'Manual'
            })) {
                $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
                $s.address_added=$false
                Save-State
            }
            $ipif = Get-NetIPInterface -InterfaceIndex $s.tun_index -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
            # Preserve a subsequent administrator's MTU edit.
            if ($s.mtu_changed -and $ipif.NlMtuBytes -eq $s.config.mtu) {
                Set-NetIPInterface -InterfaceIndex $s.tun_index -AddressFamily IPv4 -PolicyStore ActiveStore -NlMtuBytes $s.old_mtu -ErrorAction Stop
                $s.mtu_changed=$false
                Save-State
            }
        }
    } catch { $failures.Add($_.Exception.Message) }
    return @($failures.ToArray())
}
function Add-PlannedRoute($planned) {
    $created = New-NetRoute -DestinationPrefix $planned.prefix -InterfaceIndex $planned.index `
        -NextHop $planned.gateway -RouteMetric $planned.metric -Protocol NetMgmt `
        -PolicyStore ActiveStore -ErrorAction Stop
    $planned.added=$true
    $planned.instance_id=[string]$created.InstanceID
    Save-State
}
function Assert-NoFullRoutes {
    if (All-Routes | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }) {
        throw 'Existing IPv4 /1 routes conflict with GameBond; stop or review the other tunnel first'
    }
}
function Assert-OwnedQos($q, $actual) {
    if (@($actual).Count -ne 1) { throw "Expected exactly one owned QoS policy: $($q.name)" }
    $p = @($actual)[0]
    # CIM returns NetQos.Protocol (UDP=2), not IP's UDP protocol number 17.
    $protocol = [string]$p.IPProtocolMatchCondition
    $path = [string]$p.AppPathNameMatchCondition
    $dscp = [int]$p.DSCPAction
    if ($path -ine $q.path -or $dscp -ne 46 -or $protocol -notin @('UDP','2')) {
        throw "Owned QoS mismatch: path='$path'; DSCP=$dscp; NetQosProtocol='$protocol'; expected path='$($q.path)', DSCP46, UDP(2)"
    }
}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the client as administrator to configure networking'
    }
    switch ($request.phase) {
        'preflight' {
            $c = $request.config
            $all = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
            $tun = @($all | Where-Object { $_.Name -ceq $c.tun_name })
            if ($tun.Count -ne 1) { throw 'Exactly one already-created GameBond TUN is required' }
            $physical = @(Get-NetAdapter -Physical -ErrorAction Stop)
            if ($physical | Where-Object { $_.ifIndex -eq $tun[0].ifIndex }) {
                throw 'GameBond TUN must be separate from physical adapters'
            }
            $routes = @(All-Routes)
            $addresses = @(All-Addresses)
            Assert-NoFullRoutes
            foreach ($index in 0,1) {
                $ifindex = $c.interface_indices[$index]
                $adapter = @($physical | Where-Object { $_.ifIndex -eq $ifindex -and $_.Status -eq 'Up' })
                if ($adapter.Count -ne 1) { throw 'Both configured physical adapters must exist and be up' }
                $source = @($addresses | Where-Object {
                    $_.InterfaceIndex -eq $ifindex -and $_.IPAddress -eq $c.bind[$index][0] -and
                    [string]$_.AddressState -eq 'Preferred'
                })
                if ($source.Count -ne 1) { throw 'Configured source IPv4 does not belong to its physical interface in Preferred state' }
                if ($routes | Where-Object { $_.InterfaceIndex -eq $ifindex -and $_.DestinationPrefix -eq "$($c.peer[0])/32" }) {
                    throw 'An endpoint host route already exists on a configured physical interface'
                }
            }
            if ($addresses | Where-Object { $_.IPAddress -eq $c.client_tunnel_ip }) {
                throw 'The client tunnel IPv4 address already exists'
            }
            if ($addresses | Where-Object {
                $_.InterfaceIndex -eq $tun[0].ifIndex -and $_.IPAddress -notlike '169.254.*'
            }) { throw 'GameBond TUN already has a configured IPv4 address' }
            foreach ($q in @($request.qos)) {
                if (-not (Test-Path -LiteralPath $q.path -PathType Leaf)) { throw 'A configured CoD executable does not exist' }
            }
            if (@($request.qos).Count -gt 0) {
                $existing = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
                foreach ($q in @($request.qos)) {
                    if ($existing | Where-Object { $_.Name -ieq $q.name }) { throw 'A planned QoS policy name already exists' }
                }
            }
            $ipif = Get-NetIPInterface -InterfaceIndex $tun[0].ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop
            $planned = @()
            foreach ($index in 0,1) {
                $planned += @{stage='prepare'; index=$c.interface_indices[$index]; prefix="$($c.peer[0])/32"; gateway=$c.gateways[$index]; metric=$request.metric; added=$false; instance_id=$null}
            }
            foreach ($prefix in '0.0.0.0/1','128.0.0.0/1') {
                $planned += @{stage='activate'; index=$tun[0].ifIndex; prefix=$prefix; gateway='0.0.0.0'; metric=$request.metric; added=$false; instance_id=$null}
            }
            $state = @{config=$c; tun_index=$tun[0].ifIndex; tun_guid=[string]$tun[0].InterfaceGuid; old_mtu=$ipif.NlMtuBytes; routes=$planned; qos=@($request.qos); address_added=$false; mtu_changed=$false}
        }
        'prepare' {
            Check-Tun $state
            $routes = @(All-Routes)
            Assert-NoFullRoutes
            foreach ($planned in @($state.routes | Where-Object { $_.stage -eq 'prepare' })) {
                if ($routes | Where-Object { $_.InterfaceIndex -eq $planned.index -and $_.DestinationPrefix -eq $planned.prefix }) {
                    throw 'Endpoint host route appeared after preflight'
                }
            }
            if (All-Addresses | Where-Object { $_.IPAddress -eq $state.config.client_tunnel_ip }) {
                throw 'Tunnel address appeared after preflight'
            }
            foreach ($planned in @($state.routes | Where-Object { $_.stage -eq 'prepare' })) { Add-PlannedRoute $planned }
            New-NetIPAddress -InterfaceIndex $state.tun_index -IPAddress $state.config.client_tunnel_ip `
                -PrefixLength 30 -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            $state.address_added=$true
            Save-State
            Set-NetIPInterface -InterfaceIndex $state.tun_index -AddressFamily IPv4 -NlMtuBytes $state.config.mtu `
                -PolicyStore ActiveStore -ErrorAction Stop
            $state.mtu_changed=$true
            Save-State
            $ready=$false
            foreach ($attempt in 1..20) {
                $current=@(All-Addresses | Where-Object {
                    $_.InterfaceIndex -eq $state.tun_index -and $_.IPAddress -eq $state.config.client_tunnel_ip -and
                    [string]$_.AddressState -eq 'Preferred'
                })
                if ($current.Count -eq 1) { $ready=$true; break }
                Start-Sleep -Milliseconds 250
            }
            if (-not $ready) { throw 'Timed out waiting for the tunnel IPv4 address to become Preferred' }
        }
        'activate' {
            Check-Tun $state
            Assert-NoFullRoutes
            $routes = @(All-Routes)
            foreach ($planned in @($state.routes | Where-Object { $_.stage -eq 'prepare' })) {
                if (@($routes | Where-Object { Owned-Route $_ $planned }).Count -ne 1) {
                    throw 'A prepared endpoint route changed; refusing full-tunnel activation'
                }
            }
            $addresses = @(All-Addresses | Where-Object {
                $_.InterfaceIndex -eq $state.tun_index -and $_.IPAddress -eq $state.config.client_tunnel_ip -and
                $_.PrefixLength -eq 30 -and [string]$_.AddressState -eq 'Preferred'
            })
            if ($addresses.Count -ne 1) { throw 'The prepared tunnel address is not ready' }
            if (@($state.qos).Count -gt 0) {
                $existing = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
                foreach ($q in @($state.qos)) {
                    if ($existing | Where-Object { $_.Name -ieq $q.name }) { throw 'QoS policy appeared after preflight' }
                }
            }
            foreach ($planned in @($state.routes | Where-Object { $_.stage -eq 'activate' })) { Add-PlannedRoute $planned }
            foreach ($q in @($state.qos)) {
                New-NetQosPolicy -Name $q.name -AppPathNameMatchCondition $q.path -IPProtocolMatchCondition UDP -DSCPAction 46 `
                    -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
                $q.added=$true
                Save-State
            }
            # Creation success does not establish the effective match/action.
            # Verify our exact owned policies before declaring the client ready.
            $effective = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
            foreach ($q in @($state.qos)) {
                $actual = @($effective | Where-Object { $_.Name -ieq $q.name })
                if ($actual.Count -ne 1) {
                    $names = @($effective | ForEach-Object { [string]$_.Name }) -join ', '
                    throw "Expected exactly one owned QoS policy: $($q.name); count=$($actual.Count); ActiveStore names=[$names]"
                }
                Assert-OwnedQos $q $actual
                $q.verified=$true
            }
            Save-State
        }
        'close' {
            $issues = @(Remove-Owned $state)
            if ($issues.Count -gt 0) { throw ($issues -join '; ') }
        }
        'cleanup-legacy' {
            if (Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Name -ceq 'GameBond' }) {
                throw 'A GameBond adapter exists; refusing legacy cleanup while a client may be active'
            }
            $policies = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
            $matched = @()
            foreach ($policy in $policies) {
                if ($policy.Name -notmatch '^GameBond-CoD-[0-9a-f]{24}-[0-2]$') { continue }
                foreach ($property in 'AppPathNameMatchCondition','DSCPAction','IPProtocolMatchCondition') {
                    if ($null -eq $policy.PSObject.Properties[$property]) {
                        throw "Cannot safely inspect legacy QoS policy $($policy.Name): missing $property"
                    }
                }
                # Namespaced generated name + exact known path + DSCP46 + an
                # compatible protocol condition, including stale UDP policies.
                if ($request.legacy_paths -inotcontains [string]$policy.AppPathNameMatchCondition) { continue }
                if ([int]$policy.DSCPAction -ne 46) { continue }
                $protocol = [uint32]$policy.IPProtocolMatchCondition
                if ($protocol -notin @(0,2,3)) { continue } # NetQos enum None/UDP/Both.
                $matched += @{name=[string]$policy.Name; path=[string]$policy.AppPathNameMatchCondition; added=$true}
            }
            $state.qos=$matched
            $issues = @(Remove-Owned $state)
            if ($issues.Count -gt 0) { throw ($issues -join '; ') }
        }
        default { throw 'Unknown network operation' }
    }
    Save-State
    @{ok=$true; state=$state} | ConvertTo-Json -Depth 16 -Compress
} catch {
    $message = $_.Exception.Message
    $rollback = @()
    if ($request.phase -in @('prepare','activate') -and $null -ne $state) {
        $rollback = @(Remove-Owned $state)
    }
    try { Save-State } catch { $rollback += $_.Exception.Message }
    @{ok=$false; state=$state; error=$message; rollback_errors=$rollback} | ConvertTo-Json -Depth 16 -Compress
    exit 1
}
'''


class WindowsNetwork:
    """Own only this run's explicit IPv4 routes/address/MTU and QoS policies.

    close() is idempotent after successful cleanup, and retryable after cleanup
    failure. Unexpected provider failures are reported instead of ignored.
    """

    def __init__(self, config, cod_executables=(), *, journal_dir=None):
        _require_windows_admin()
        if config.get("role") != "client":
            raise ValueError("Windows auto-configuration supports client mode only")
        bind, indices, gateways = (config.get(name) for name in
                                   ("bind", "interface_indices", "gateways"))
        if (not isinstance(bind, list) or not MIN_LINKS<=len(bind)<=MAX_LINKS or
                not isinstance(indices, list) or len(indices) != len(bind) or
                any(type(i) is not int or i <= 0 for i in indices) or len(set(indices)) != len(bind) or
                not isinstance(gateways, list) or len(gateways) != len(bind)):
            raise ValueError("2 to 8 binds with matching distinct interface_indices and gateways are required")
        source_ips = []
        for source, gateway in zip(bind, gateways):
            if not isinstance(source, (list, tuple)) or len(source) != 2:
                raise ValueError("bind entries must contain IPv4 and port")
            if type(source[1]) is not int or not 0 <= source[1] <= 65535:
                raise ValueError("bind port must be 0..65535")
            ip, route_gateway = ipaddress.IPv4Address(source[0]), ipaddress.IPv4Address(gateway)
            if any(address.is_unspecified or address.is_loopback or address.is_multicast
                   or address.is_link_local for address in (ip, route_gateway)):
                raise ValueError("physical source and gateway must be usable IPv4 addresses")
            source_ips.append(str(ip))
        if len(set(source_ips)) != len(bind):
            raise ValueError("The legacy route backend requires distinct source IPv4 addresses")
        peer = config.get("peer")
        if not isinstance(peer, (list, tuple)) or len(peer) != 2:
            raise ValueError("a fixed IPv4 peer is required")
        if type(peer[1]) is not int or not 1 <= peer[1] <= 65535:
            raise ValueError("peer port must be 1..65535")
        endpoint = ipaddress.IPv4Address(peer[0])
        if endpoint.is_unspecified or endpoint.is_loopback or endpoint.is_multicast:
            raise ValueError("peer must be a usable IPv4 endpoint")
        tunnel_ip = ipaddress.IPv4Address(config["client_tunnel_ip"])
        if tunnel_ip == endpoint or tunnel_ip.is_unspecified or tunnel_ip.is_multicast:
            raise ValueError("invalid client tunnel IPv4 address")
        # The current server and setup scripts use a /30 IPv4 tunnel.
        network = ipaddress.IPv4Network(f"{tunnel_ip}/30", strict=False)
        if tunnel_ip in (network.network_address, network.broadcast_address):
            raise ValueError("client tunnel IPv4 must be a /30 host address")
        name, mtu = config.get("tun_name", "GameBond"), config.get("mtu", 1280)
        if not isinstance(name, str) or not name or "\0" in name:
            raise ValueError("a valid owned tunnel name is required")
        if type(mtu) is not int or not 1280 <= mtu <= 1400:
            raise ValueError("tunnel MTU must be 1280..1400")
        paths = list(cod_executables)
        if any(not isinstance(path, str) or not ntpath.isabs(path) or "\0" in path
               or not path.casefold().endswith(".exe") for path in paths):
            raise ValueError("CoD paths must identify absolute executable files")
        if len(set(path.casefold() for path in paths)) != len(paths):
            raise ValueError("CoD executable paths must be distinct")
        self._config = {"role": "client", "bind": [[ip, source[1]] for ip, source in zip(source_ips, bind)],
                        "interface_indices": list(indices), "gateways": list(gateways),
                        "peer": [str(endpoint), peer[1]], "client_tunnel_ip": str(tunnel_ip),
                        "tun_name": name, "mtu": mtu}
        token = secrets.token_hex(12)
        self._qos = [{"name": f"GameBond-CoD-{token}-{i}", "path": path, "added": False, "verified": False}
                     for i, path in enumerate(paths)]
        self._metric = 20000 + secrets.randbelow(10000)
        self._journal_dir = Path(journal_dir) if journal_dir is not None else _default_journal_dir()
        self._journal_path = self._journal_dir / f"{token}.json"
        self._owner = {"pid": os.getpid(), "created": _process_created(os.getpid())}
        self._state = None
        self._prepared = False
        self._active = False
        self._closed = False

    def _call(self, phase, **extra):
        if self._journal_path is not None:
            self._journal_dir.mkdir(parents=True, exist_ok=True)
        payload = {"phase": phase, "state": self._state,
                   "journal_path": str(self._journal_path.resolve()) if self._journal_path is not None else None,
                   "owner": self._owner, **extra}
        executable = ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                 "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        # Do not timeout/kill a mutating PowerShell transaction halfway through:
        # the fixed script catches provider errors and rolls back synchronously.
        # A normal signal shutdown invokes close() after workers have stopped.
        completed = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL],
            input=json.dumps(payload, ensure_ascii=False), capture_output=True,
            text=True, encoding="utf-8", errors="replace", check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        try:
            response = json.loads(completed.stdout.strip())
        except (ValueError, TypeError) as exc:
            detail = completed.stderr.strip() or completed.stdout.strip() or "no response"
            raise WindowsNetworkError(f"Windows network {phase} returned an invalid transcript: {detail}") from exc
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise WindowsNetworkError(f"Windows network {phase} returned an invalid response")
        # Preserve the planned identities even when a mutation/rollback failed,
        # so the caller can retry close() without touching unrelated routes.
        if response.get("state") is not None:
            self._state = response["state"]
            self._save_journal()
        if completed.returncode != 0 or not response["ok"]:
            message = response.get("error") or completed.stderr.strip() or f"exit {completed.returncode}"
            rollback = response.get("rollback_errors", [])
            if rollback:
                message += "; rollback errors: " + "; ".join(str(item) for item in rollback)
            raise WindowsNetworkError(f"Windows network {phase} failed: {message}")
        return response

    def _save_journal(self):
        if self._journal_path is None or self._state is None:
            return
        self._journal_dir.mkdir(parents=True, exist_ok=True)
        record = {"version": 1, "owner": self._owner, "worker": None, "state": self._state}
        temporary = self._journal_path.with_suffix(".tmp-" + secrets.token_hex(6))
        try:
            with temporary.open("x", encoding="utf-8") as file:
                json.dump(record, file, ensure_ascii=False)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self._journal_path)
        finally:
            temporary.unlink(missing_ok=True)

    def prepare(self):
        if self._closed:
            raise WindowsNetworkError("Windows network helper is closed")
        if self._prepared:
            return
        try:
            recover_journals(self._journal_dir, exclude=self._journal_path)
            self._call("preflight", config=self._config, qos=self._qos, metric=self._metric)
            if not isinstance(self._state, dict) or not self._state.get("routes"):
                raise WindowsNetworkError("Network preflight did not return planned object identities")
            self._call("prepare")
            self._prepared = True
        except Exception as original:
            if self._state is not None:
                try:
                    self.close()
                except Exception as cleanup:
                    raise WindowsNetworkError(f"{original}; cleanup failed: {cleanup}") from original
            raise

    def activate(self):
        if not self._prepared or self._closed:
            raise WindowsNetworkError("prepare() is required before activation")
        if self._active:
            return
        try:
            self._call("activate")
            self._active = True
        except Exception as original:
            try:
                self.close()
            except Exception as cleanup:
                raise WindowsNetworkError(f"{original}; cleanup failed: {cleanup}") from original
            raise

    def qos_status(self):
        """Return only the owned policy readback, for startup log verification."""
        return [{"name": q["name"], "path": q["path"], "dscp": 46,
                 "protocol": "UDP", "verified": q.get("verified", False)}
                for q in (self._state or {}).get("qos", [])]

    def close(self):
        if self._closed:
            return
        if self._state is not None:
            self._call("close")
        if self._journal_path is not None:
            self._journal_path.unlink(missing_ok=True)
        self._prepared = self._active = False
        self._closed = True

    def __enter__(self):
        self.prepare()
        return self

    def __exit__(self, *_):
        self.close()


def _default_journal_dir():
    return Path(__file__).resolve().parent.parent / ".runtime" / "network"


def _process_created(pid):
    """Windows process creation FILETIME; missing PID is None, denial is fatal."""
    if sys.platform != "win32":
        return None  # Unit tests mock OS operations; runtime is Windows-only.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int
    handle = kernel.OpenProcess(0x1000, False, int(pid))
    if not handle:
        code = ctypes.get_last_error()
        if code == 87:  # ERROR_INVALID_PARAMETER: PID no longer exists.
            return None
        raise WindowsNetworkError(f"Cannot verify journal process {pid}: {ctypes.WinError(code)}")
    try:
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
            raise ctypes.WinError(ctypes.get_last_error())
        return str(times[0].value)
    finally:
        kernel.CloseHandle(handle)


def _record_is_live(record):
    if not isinstance(record, dict) or type(record.get("pid")) is not int or record["pid"] <= 0:
        return False
    created = _process_created(record["pid"])
    return created is not None and str(created) == str(record.get("created"))


def _read_journal(path):
    path = Path(path)
    if path.is_symlink():
        raise WindowsNetworkError(f"Refusing a symlink journal: {path}")
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("version") != 1 or not isinstance(record.get("state"), dict):
        raise WindowsNetworkError(f"Invalid network journal: {path}")
    state = record["state"]
    for route in state.get("routes", []):
        if route.get("prefix") not in ("0.0.0.0/1", "128.0.0.0/1"):
            network = ipaddress.IPv4Network(route["prefix"])
            if network.prefixlen != 32:
                raise WindowsNetworkError("Recovery journal contains an unexpected route")
        if (type(route.get("index")) is not int or route["index"] <= 0 or
                type(route.get("metric")) is not int or not 20000 <= route["metric"] < 30000 or
                type(route.get("added")) is not bool):
            raise WindowsNetworkError("Recovery journal contains invalid route ownership")
        ipaddress.IPv4Address(route["gateway"])
    for qos in state.get("qos", []):
        if not re.fullmatch(r"GameBond-CoD-[0-9a-f]{24}-[0-9]+", qos.get("name", "")):
            raise WindowsNetworkError("Recovery journal contains an unexpected QoS policy")
    return record


def cleanup_journal(path):
    """Recover one previous run, refusing a live owner or hidden PS worker."""
    _require_windows_admin()
    path = Path(path)
    record = _read_journal(path)
    if _record_is_live(record.get("owner")) or _record_is_live(record.get("worker")):
        raise WindowsNetworkError(f"Network journal still belongs to a live process: {path}")
    helper = WindowsNetwork.__new__(WindowsNetwork)
    helper._state = record["state"]
    helper._owner = {"pid": os.getpid(), "created": _process_created(os.getpid())}
    helper._journal_path, helper._journal_dir = path, path.parent
    helper._prepared = helper._active = helper._closed = False
    helper.close()


def recover_journals(directory=None, *, exclude=None):
    """Recover stale ownership records before attempting a fresh preflight."""
    directory = Path(directory) if directory is not None else _default_journal_dir()
    for path in sorted(directory.glob("*.json")):
        if exclude is None or path.resolve() != Path(exclude).resolve():
            cleanup_journal(path)


def cleanup_legacy():
    """Recover captured routes once and stale, strictly identified GameBond QoS."""
    _require_windows_admin()
    root = Path(__file__).resolve().parent.parent
    marker = root / ".runtime" / "legacy-cleanup-complete.json"
    if not marker.exists() and _process_created(29196) is not None:
        raise WindowsNetworkError("Legacy owner PID29196 exists; refusing legacy cleanup")
    path = root / "configs" / "legacy-network-ownership.json"
    record = (_read_journal(path) if not marker.exists() else {"state": {
        "routes": [], "qos": [], "tun_index": -1, "tun_guid": "",
        "config": {"tun_name": "GameBond"}, "address_added": False, "mtu_changed": False}})
    helper = WindowsNetwork.__new__(WindowsNetwork)
    helper._state, helper._owner = record["state"], None
    helper._journal_path = helper._journal_dir = None
    helper._prepared = helper._active = helper._closed = False
    helper._call("cleanup-legacy", legacy_paths=[
        r"C:\XboxGames\Call of Duty\Content\cod.exe",
        r"C:\XboxGames\Call of Duty\Content\cod25\cod25-cod.exe",
        r"C:\XboxGames\Call of Duty\Content\sp26\sp26-cod.exe"])
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"completed": True, "legacy_owner_pid": 29196}), encoding="utf-8")
    return [entry["name"] for entry in helper._state.get("qos", [])]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Recover only recorded GameBond Windows network objects")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("cleanup-legacy", help="recover the two captured routes and strictly identified old CoD QoS")
    cleanup = sub.add_parser("cleanup", help="recover a stale run journal; refuses live owners")
    cleanup.add_argument("--journal")
    args = parser.parse_args()
    if args.command == "cleanup-legacy":
        print(json.dumps({"removed_legacy_qos": cleanup_legacy()}))
    elif args.journal:
        cleanup_journal(args.journal)
    else:
        recover_journals()
    print("Recorded GameBond network cleanup completed")


if __name__ == "__main__":
    main()
