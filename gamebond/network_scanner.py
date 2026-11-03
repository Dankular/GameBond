"""Passive Windows neighbor inventory and explicit bounded local discovery.

Importing or taking an inventory never probes the LAN. ``DiscoveryJob.start``
is the sole active entry point and validates a private subnet and source adapter.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import ctypes
import ipaddress
import json
import os
import socket
import struct
import subprocess
import threading
import time
import math
from pathlib import Path
import secrets

HIDDEN = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))

INVENTORY_SCRIPT = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$links=@(Get-NetAdapter | Select-Object Name,ifIndex,Status,MacAddress,InterfaceDescription)
$addresses=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
 Where-Object {$_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*'} |
 Select-Object -First 129 |
 ForEach-Object {
  $ip=$_;$adapter=$links | Where-Object {$_.ifIndex -eq $ip.InterfaceIndex} | Select-Object -First 1
  [pscustomobject]@{index=[int]$ip.InterfaceIndex;name=$ip.InterfaceAlias;address=$ip.IPAddress;
   prefix_length=[int]$ip.PrefixLength;up=($adapter.Status -eq 'Up');mac=$adapter.MacAddress;
   description=$adapter.InterfaceDescription}
 })
$neighbors=@(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
 Select-Object -First 4097 |
 Select-Object @{n='interface_index';e={[int]$_.InterfaceIndex}},
 @{n='address';e={$_.IPAddress}},@{n='mac';e={$_.LinkLayerAddress}},@{n='state';e={$_.State.ToString()}})
ConvertTo-Json -InputObject ([pscustomobject]@{adapters=$addresses;neighbors=$neighbors}) -Depth 5 -Compress
'''


def normalize_inventory(record):
    if not isinstance(record, dict):
        raise ValueError('Invalid network inventory')
    adapters = []
    for row in record.get('adapters', []):
        try:
            address = ipaddress.IPv4Address(row['address'])
            interface = ipaddress.IPv4Interface(f"{address}/{int(row['prefix_length'])}")
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                continue
            adapters.append(dict(index=int(row['index']), name=str(row['name']),
                address=str(address), prefix_length=interface.network.prefixlen,
                subnet=str(interface.network),
                discovery_subnet=str(ipaddress.IPv4Interface(f'{address}/{max(24,interface.network.prefixlen)}').network),
                up=bool(row['up']), mac=str(row.get('mac') or ''),
                description=str(row.get('description') or '')))
        except (ValueError, TypeError, KeyError):
            continue
    neighbors = []
    for row in record.get('neighbors', []):
        try:
            address = ipaddress.IPv4Address(row['address'])
            mac = str(row.get('mac') or '').replace('-', ':').lower()
            if address.is_multicast or address.is_unspecified or address.is_loopback or address == ipaddress.IPv4Address('255.255.255.255'):
                continue
            if not mac or mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                continue
            state = str(row['state'])
            if state.lower() in ('incomplete', 'unreachable'):
                continue
            neighbors.append(dict(interface_index=int(row['interface_index']), address=str(address),
                mac=mac, state=state, source='neighbor_cache', reachable_now=state.lower() == 'reachable',
                hostname=None, vendor=None))
        except (ValueError, TypeError, KeyError):
            continue
    unique = {(row['interface_index'], row['address']): row for row in neighbors}
    return dict(observed_at=time.time(), adapters=adapters[:128],
                devices=sorted(unique.values(), key=lambda row: (row['interface_index'], int(ipaddress.ip_address(row['address']))))[:4096],
                coverage=dict(adapters_returned=min(128,len(adapters)), devices_returned=min(4096,len(unique)),
                    adapter_limit_reached=len(record.get('adapters',[]))>=129,
                    neighbor_limit_reached=len(record.get('neighbors',[]))>=4097),
                active_probe=False, limitations=['Neighbor-cache entries do not prove a device is currently online.',
                                                'Hostnames and hardware vendors are not inferred from IP/MAC addresses.'])


def inventory():
    if os.name != 'nt':
        raise RuntimeError('Windows neighbor inventory is unavailable on this host')
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', INVENTORY_SCRIPT],
                            capture_output=True, timeout=12, creationflags=HIDDEN)
    if result.returncode:
        raise RuntimeError('Windows could not enumerate local adapters and neighbors')
    return normalize_inventory(json.loads(result.stdout.decode('utf-8-sig')))


class DeviceHistory:
    """First/last observations by GameBond, not inferred device uptime."""
    def __init__(self,path=None,limit=4096):
        if not 1<=limit<=4096:raise ValueError('Invalid device history limit')
        self.path=Path(path) if path is not None else None
        self.limit=limit;self.records={};self.lock=threading.Lock()
        if self.path and self.path.exists():
            if self.path.stat().st_size>4*1024*1024:raise ValueError('Device history is too large')
            record=json.loads(self.path.read_text())
            if record.get('version')!=1 or not isinstance(record.get('devices'),dict):raise ValueError('Invalid device history')
            if len(record['devices'])>limit:raise ValueError('Device history exceeds its limit')
            for key,value in record['devices'].items():
                if set(value)!= {'first_seen','last_seen'} or any(type(v) not in (int,float) or not math.isfinite(v) or v<0 for v in value.values()):
                    raise ValueError('Invalid device observation timestamp')
            self.records=record['devices']

    def observe(self,devices,observed_at=None):
        observed_at=time.time() if observed_at is None else observed_at
        rows=[]
        with self.lock:
            for device in devices:
                row=dict(device)
                key=str(device.get('interface_index'))+':'+str(device.get('mac') or device['address']).lower()
                record=self.records.setdefault(key,dict(first_seen=observed_at,last_seen=observed_at))
                record['first_seen']=min(record['first_seen'],observed_at)
                record['last_seen']=max(record['last_seen'],observed_at)
                row.update(record);rows.append(row)
            for key in sorted(self.records,key=lambda k:self.records[k]['last_seen'])[:-self.limit]:del self.records[key]
            if self.path:
                self.path.parent.mkdir(parents=True,exist_ok=True)
                temporary=self.path.with_name(self.path.name+'.'+secrets.token_hex(4)+'.tmp')
                try:
                    temporary.write_text(json.dumps(dict(version=1,devices=self.records)),encoding='utf-8')
                    os.replace(temporary,self.path)
                finally:
                    if temporary.exists():temporary.unlink()
        return rows


def validate_scan(subnet, source_address, interface_index, adapters, max_hosts=256):
    if not 1 <= max_hosts <= 256:
        raise ValueError('Discovery is limited to 256 addresses')
    network = ipaddress.IPv4Network(subnet, strict=True)
    source = ipaddress.IPv4Address(source_address)
    if not any(network.subnet_of(private) for private in PRIVATE_NETWORKS):
        raise ValueError('Choose an RFC1918 private local subnet')
    selected = next((row for row in adapters if row['index'] == interface_index and row['address'] == str(source) and row['up']), None)
    if selected is None:
        raise ValueError('The selected source address is not on an active adapter')
    local_network = ipaddress.IPv4Network(selected['subnet'], strict=True)
    if source not in network or not network.subnet_of(local_network):
        raise ValueError('Discovery must stay inside the selected adapter subnet')
    if network.num_addresses > max_hosts + 2:
        raise ValueError('Choose a smaller local subnet (at most 256 addresses)')
    targets = [str(address) for address in network.hosts() if address != source]
    if len(targets) > max_hosts:
        raise ValueError('Too many discovery targets')
    return str(source), targets


def icmp_probe(source, target, timeout_ms=400):
    """Synchronous IPv4 ICMP using an explicit local source, without raw sockets."""
    if os.name != 'nt':
        raise RuntimeError('Source-bound Windows ICMP is unavailable')
    if not 50 <= timeout_ms <= 1500:
        raise ValueError('Discovery timeout must be 50..1500 milliseconds')
    api = ctypes.WinDLL('iphlpapi', use_last_error=True)
    api.IcmpCreateFile.argtypes = []
    api.IcmpCreateFile.restype = ctypes.c_void_p
    api.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    api.IcmpCloseHandle.restype = ctypes.c_bool
    api.IcmpSendEcho2Ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint16, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    api.IcmpSendEcho2Ex.restype = ctypes.c_uint32
    handle = api.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    request = ctypes.create_string_buffer(b'GameBond discovery')
    reply = ctypes.create_string_buffer(512)
    try:
        count = api.IcmpSendEcho2Ex(handle, None, None, None,
            struct.unpack('=I', socket.inet_aton(source))[0], struct.unpack('=I', socket.inet_aton(target))[0],
            request, len(request.raw)-1, None, reply, len(reply), timeout_ms)
        if not count:
            return dict(address=target, responded=False, status=ctypes.get_last_error(), rtt_ms=None)
        address, status, rtt = struct.unpack_from('<III', reply.raw)
        responding = socket.inet_ntoa(struct.pack('=I', address))
        return dict(address=target, responded=status == 0 and responding == target,
                    status=status, rtt_ms=rtt if status == 0 else None)
    finally:
        api.IcmpCloseHandle(handle)


class DiscoveryJob:
    def __init__(self, subnet, source_address, interface_index, *, adapters=None,
                 workers=12, timeout_ms=400, max_hosts=256, probe=icmp_probe):
        if type(interface_index) is not int or interface_index <= 0:
            raise ValueError('Choose a valid local adapter')
        if not 1 <= workers <= 16 or not 50 <= timeout_ms <= 1500:
            raise ValueError('Invalid discovery concurrency or timeout')
        self.subnet = str(subnet)
        self.interface_index = interface_index
        self._adapters = adapters
        self.source, self.targets = validate_scan(subnet, source_address, interface_index,
            inventory()['adapters'] if adapters is None else adapters, max_hosts)
        self.workers, self.timeout_ms, self.probe = workers, timeout_ms, probe
        self.cancel_event = threading.Event()
        self.lock = threading.Lock()
        self.thread = None
        self.state = 'ready'
        self.results = []
        self.errors = []
        self.started_at = self.finished_at = None

    def start(self):
        with self.lock:
            if self.thread is not None:
                raise RuntimeError('This discovery job has already been started')
            # Check again at execution time so an old dialog cannot scan using
            # a source adapter that has since gone down or changed address.
            if self._adapters is None:
                validate_scan(self.subnet, self.source, self.interface_index, inventory()['adapters'])
            self.state = 'running'; self.started_at = time.time()
            self.thread = threading.Thread(target=self._run, name='gamebond-lan-discovery', daemon=True)
            self.thread.start()
        return self

    def cancel(self):
        self.cancel_event.set()

    def snapshot(self):
        with self.lock:
            return dict(state=self.state, subnet=self.subnet, source_address=self.source,
                interface_index=self.interface_index, total=len(self.targets), completed=len(self.results),
                results=list(self.results), errors=list(self.errors),
                started_at=self.started_at, finished_at=self.finished_at, active_probe=True,
                limitations=['Non-responsive devices can still be online or block ICMP.',
                            'Discovery sends one source-bound ICMP request per selected local address.'])

    def _run(self):
        targets = iter(self.targets)
        pending = {}
        try:
            with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix='gamebond-lan-probe') as executor:
                def fill():
                    while len(pending) < self.workers and not self.cancel_event.is_set():
                        target = next(targets, None)
                        if target is None:
                            break
                        pending[executor.submit(self.probe, self.source, target, self.timeout_ms)] = target
                fill()
                while pending:
                    completed, _ = wait(pending, timeout=.1, return_when=FIRST_COMPLETED)
                    for future in completed:
                        target = pending.pop(future)
                        if future.cancelled():
                            continue
                        try:
                            result = future.result()
                            with self.lock:
                                self.results.append(result)
                        except Exception as exc:
                            with self.lock:
                                self.results.append(dict(address=target, responded=False, status='error', rtt_ms=None))
                                if len(self.errors) < 16:
                                    self.errors.append(str(exc))
                    if self.cancel_event.is_set():
                        for future in list(pending):
                            future.cancel()
                    else:
                        fill()
            with self.lock:
                self.state = 'cancelled' if self.cancel_event.is_set() else 'completed'
        except Exception as exc:
            with self.lock:
                self.state = 'failed'; self.errors.append(str(exc))
        finally:
            with self.lock:
                self.finished_at = time.time()
