"""Transactional exact-host NRPT scope for GameBond's temporary DNS responder.

Rules are local NRPT policy objects, not hosts-file or adapter DNS changes.
They survive an abrupt process exit, so every planned random identity is
journalled before creation and recovered only after both owner processes exit.
Existing DNS caches and applications using their own resolver are unaffected.
"""
from __future__ import annotations

import ipaddress
import json
import ntpath
import os
from pathlib import Path
import re
import secrets
import subprocess

from .windows_network import _require_windows_admin, _process_created, _record_is_live


class WindowsDnsError(RuntimeError):
    pass


def _hostname(value):
    if not isinstance(value, str):
        raise ValueError("DNS namespace must be an exact hostname")
    name = value.lower().removesuffix(".")
    if (not 1 < len(name) <= 253 or "." not in name or
            any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in name.split("."))):
        raise ValueError("DNS namespaces must be exact ASCII FQDNs, without wildcards or suffix rules")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("DNS namespace must be a hostname, not an IP address")


def _resolver(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or int(address) == 0xffffffff:
        raise ValueError("DNS resolver must be a usable IPv4 address")
    return str(address)


_POWERSHELL = r'''
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
'''


def _default_journal_dir():
    return Path(__file__).resolve().parent.parent / ".runtime" / "dns"


class WindowsDnsScope:
    def __init__(self, namespaces, resolver_ip, *, journal_dir=None):
        _require_windows_admin()
        if isinstance(namespaces, (str, bytes)):
            raise ValueError("namespaces must be a collection of exact hostnames")
        names = []
        for value in namespaces:
            names.append(_hostname(value))
            if len(names) > 128:
                raise ValueError("at most 128 DNS namespaces are supported")
        if not names or len(set(names)) != len(names):
            raise ValueError("1..128 distinct DNS namespaces are required")
        token = secrets.token_hex(12)
        self._state = {"resolver_ip": _resolver(resolver_ip), "rules": [
            {"namespace": name, "marker": f"GameBond-DNS-{token}-{index}",
             "guid": None, "verified": False} for index, name in enumerate(names)]}
        self._journal_dir = Path(journal_dir) if journal_dir is not None else _default_journal_dir()
        self._journal_path = self._journal_dir / f"{token}.json"
        self._owner = {"pid": os.getpid(), "created": _process_created(os.getpid())}
        self._active = self._closed = False

    def _save_journal(self):
        self._journal_dir.mkdir(parents=True, exist_ok=True)
        record = {"version": 1, "kind": "GameBond-DNS", "owner": self._owner,
                  "worker": None, "state": self._state}
        temporary = self._journal_path.with_suffix(".tmp-" + secrets.token_hex(6))
        try:
            with temporary.open("x", encoding="utf-8") as output:
                json.dump(record, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self._journal_path)
        finally:
            temporary.unlink(missing_ok=True)

    def _call(self, phase):
        self._save_journal()
        executable = ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                 "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        completed = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL],
            input=json.dumps({"phase": phase, "state": self._state, "owner": self._owner,
                              "journal_path": str(self._journal_path.resolve())}),
            text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        try:
            response = json.loads(completed.stdout.strip())
        except (ValueError, TypeError) as exc:
            raise WindowsDnsError(f"DNS {phase} returned an invalid transcript: {completed.stderr or completed.stdout}") from exc
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise WindowsDnsError(f"DNS {phase} returned an invalid response")
        if isinstance(response.get("state"), dict):
            self._state = response["state"]
            self._save_journal()
        if completed.returncode or not response["ok"]:
            message = response.get("error", f"exit {completed.returncode}")
            if response.get("rollback_errors"):
                message += "; rollback errors: " + "; ".join(map(str, response["rollback_errors"]))
            raise WindowsDnsError(f"DNS {phase} failed: {message}")

    def activate(self):
        if self._closed:
            raise WindowsDnsError("DNS scope is closed")
        if self._active:
            return
        recover_journals(self._journal_dir, exclude=self._journal_path)
        try:
            self._call("activate")
            if not all(rule.get("verified") for rule in self._state["rules"]):
                raise WindowsDnsError("DNS activation did not verify every owned rule")
            self._active = True
        except Exception as original:
            try:
                self.close()
            except Exception as cleanup:
                raise WindowsDnsError(f"{original}; cleanup failed: {cleanup}") from original
            raise

    def close(self):
        if self._closed:
            return
        if self._journal_path.exists():
            self._call("close")
            self._journal_path.unlink()
        for rule in self._state["rules"]:
            rule["verified"] = False
        self._active = False
        self._closed = True

    def status(self):
        return {"active": self._active, "resolver_ip": self._state["resolver_ip"],
                "namespaces": [r["namespace"] for r in self._state["rules"]],
                "rules": [dict(rule) for rule in self._state["rules"]]}


def _read_journal(path):
    if path.is_symlink() or path.stat().st_size > 128 * 1024:
        raise WindowsDnsError("Refusing symlink or oversized DNS journal")
    record = json.loads(path.read_text(encoding="utf-8"))
    if (record.get("version") != 1 or record.get("kind") != "GameBond-DNS"
            or not isinstance(record.get("state"), dict)):
        raise WindowsDnsError("Invalid DNS journal")
    state = record["state"]
    _resolver(state["resolver_ip"])
    rules = state.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 128:
        raise WindowsDnsError("Invalid DNS journal rules")
    names = set()
    token = path.stem
    if not re.fullmatch(r"[0-9a-f]{24}", token):
        raise WindowsDnsError("Invalid DNS journal token")
    for index, rule in enumerate(rules):
        name = _hostname(rule["namespace"])
        if (name != rule["namespace"] or name in names or rule.get("marker") != f"GameBond-DNS-{token}-{index}"
                or type(rule.get("verified")) is not bool
                or (rule.get("guid") is not None and not re.fullmatch(
                    r"\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?", rule["guid"]))):
            raise WindowsDnsError("Invalid DNS journal ownership fields")
        names.add(name)
    for process in (record.get("owner"), record.get("worker")):
        if process is not None and (not isinstance(process, dict) or type(process.get("pid")) is not int
                                    or process["pid"] <= 0 or not isinstance(process.get("created"), str)):
            raise WindowsDnsError("Invalid DNS journal process identity")
    if record.get("owner") is None:
        raise WindowsDnsError("DNS journal has no owner identity")
    return record


def cleanup_journal(path):
    _require_windows_admin()
    path = Path(path)
    record = _read_journal(path)
    if _record_is_live(record["owner"]) or _record_is_live(record.get("worker")):
        raise WindowsDnsError(f"DNS journal belongs to a live process: {path}")
    helper = WindowsDnsScope.__new__(WindowsDnsScope)
    helper._state = record["state"]
    helper._journal_path, helper._journal_dir = path, path.parent
    helper._owner = {"pid": os.getpid(), "created": _process_created(os.getpid())}
    helper._active = helper._closed = False
    helper.close()


def recover_journals(directory=None, *, exclude=None):
    directory = Path(directory) if directory is not None else _default_journal_dir()
    for path in sorted(directory.glob("*.json")):
        if exclude is None or path.resolve() != Path(exclude).resolve():
            cleanup_journal(path)
