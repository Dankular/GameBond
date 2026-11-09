"""Read-only network monitoring and atomic next-connection link selection."""
from __future__ import annotations
from collections import deque
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time

import psutil
from .link_limits import MIN_LINKS,MAX_LINKS,stable_adapter_ids,valid_interface_indices

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT/'configs/local-client.json'


def save_applications(mode, applications, config_path=CONFIG):
    from .capture import normalize_apps
    if mode not in ('all','selected'):raise ValueError('Choose All apps or Selected apps')
    applications=normalize_apps(applications)
    path=Path(config_path);original=path.read_bytes();config=json.loads(original)
    config['capture_mode']=mode;config['cod_executables']=applications
    if path.read_bytes()!=original:raise RuntimeError('Configuration changed; try saving again')
    temporary=path.with_name(path.name+'.apps-'+secrets.token_hex(4))
    try:
        temporary.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()
    return config


def save_link_policies(policies,config_path=CONFIG):
    from .link_policy import LinkPolicy
    if not isinstance(policies,dict) or len(policies)>64:raise ValueError('Invalid link settings')
    normalized={}
    for index,policy in policies.items():
        if not str(index).isdigit() or int(index)<=0:raise ValueError('Invalid adapter identifier')
        normalized[str(index)]=LinkPolicy(**policy).to_dict()
    path=Path(config_path);original=path.read_bytes();config=json.loads(original)
    if all(normalized.get(str(index),{}).get('role','primary')=='never' for index in config['interface_indices']):
        raise ValueError('Keep at least one selected link enabled')
    config['link_policies']=normalized
    if path.read_bytes()!=original:raise RuntimeError('Configuration changed; try saving again')
    temporary=path.with_name(path.name+'.links-'+secrets.token_hex(4))
    try:
        temporary.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8');os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()
    return config


def discover_links():
    script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$rows=@(Get-NetAdapter -Physical | ForEach-Object {
 $a=$_
 $ips=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
   Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
   Select-Object -ExpandProperty IPAddress)
 $routes=@(Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
   Sort-Object RouteMetric)
 [pscustomobject]@{name=$a.Name; description=$a.InterfaceDescription; index=[int]$a.ifIndex;
  up=($a.Status -eq 'Up'); addresses=$ips; gateway=$(if($routes.Count){$routes[0].NextHop}else{''})}
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
'''
    result = subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',script],
                            capture_output=True,timeout=12,
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:
        raise RuntimeError('Windows could not enumerate physical adapters')
    rows = json.loads(result.stdout.decode('utf-8-sig'))
    rows=rows if isinstance(rows,list) else [rows]
    from .windows_adapters import discover_adapters
    identities={row['index']:row['id'] for row in discover_adapters()}
    for row in rows:row['id']=identities.get(row['index'],'')
    return rows


def usb_adapter_indices():
    """Windows interface indices backed by USB hardware. Best effort: any failure yields an empty set."""
    script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$rows=@(Get-NetAdapter -Physical | Where-Object { $_.PnPDeviceID -like 'USB\*' } | ForEach-Object { [int]$_.ifIndex })
ConvertTo-Json -InputObject $rows -Compress
'''
    try:
        result = subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',script],
                                capture_output=True,timeout=12,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode:return set()
        rows = json.loads(result.stdout.decode('utf-8-sig') or '[]')
        return {int(v) for v in (rows if isinstance(rows,list) else [rows])}
    except (OSError,ValueError,subprocess.SubprocessError):
        return set()


def lan_candidates(links, config):
    """Adapters that can serve a connected device: everything physical that is not a selected uplink."""
    ids = {v.casefold() for v in config.get('interface_ids',[]) if v}
    indices = set(config.get('interface_indices',[]))
    usb = usb_adapter_indices() if os.name == 'nt' else set()
    rows = []
    for row in links:
        identity = (row.get('id') or '').casefold()
        if (identity and identity in ids) or (not identity and row['index'] in indices):continue
        rows.append(dict(row, usb=row['index'] in usb))
    return sorted(rows, key=lambda r: (not r['usb'], r.get('name','')))


def save_lan_devices(devices, config_path=CONFIG):
    """Atomically store `lan_devices` after full validation against the rest of the configuration."""
    from .lan_gateway import load_lan_devices
    path = Path(config_path);original = path.read_bytes();config = json.loads(original)
    config['lan_devices'] = list(devices)
    load_lan_devices(config)
    if path.read_bytes() != original:raise RuntimeError('Configuration changed; try saving again')
    temporary = path.with_name(path.name+'.lan-'+secrets.token_hex(4))
    try:
        temporary.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
        from .atomic_io import replace_file
        replace_file(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()
    return config


class RateSampler:
    """Counter deltas over actual elapsed time; resets never invent traffic."""
    def __init__(self):
        self.previous = {}
        self.usage = {}

    def sample(self, counters, now):
        result = {}
        for name, (received, sent) in counters.items():
            old = self.previous.get(name)
            down = up = 0.0
            usage = self.usage.setdefault(name,[0,0])
            if old is not None and now > old[0]:
                elapsed = now-old[0]
                # Counter resets / adapter replacement establish a fresh baseline.
                if received >= old[1] and sent >= old[2]:
                    rx,tx = received-old[1],sent-old[2]
                    down,up = rx/elapsed,tx/elapsed
                    usage[0] += rx; usage[1] += tx
            self.previous[name] = (now,received,sent)
            result[name] = dict(down=down,up=up,received=usage[0],sent=usage[1])
        # Reappearing interfaces must establish a baseline, not bridge downtime.
        self.previous = {name:value for name,value in self.previous.items() if name in counters}
        return result


class TunnelRateSampler:
    """Independent counters: successful app I/O versus encrypted UDP payloads."""
    def __init__(self):
        self.pid=None;self.sampler=RateSampler()

    def sample(self,runtime,now):
        if not runtime:
            self.pid=None;self.sampler=RateSampler()
            return dict(application=None,encrypted=None,ip=None)
        if runtime.get('pid')!=self.pid:
            self.pid=runtime.get('pid');self.sampler=RateSampler()
        transport=runtime.get('transport',{})
        counters={'encrypted':(transport.get('rx_bytes',0),transport.get('tx_bytes',0)),
                  'ip':(transport.get('rx_payload_bytes',0),transport.get('tx_payload_bytes',0))}
        application=runtime.get('application')
        if application:
            counters['application']=(application['downloaded_bytes'],application['uploaded_bytes'])
        rates=self.sampler.sample(counters,now)
        return dict(application=rates.get('application'),encrypted=rates.get('encrypted'),ip=rates.get('ip'))


def save_selection(indices, config_path=CONFIG, links=None):
    if not MIN_LINKS<=len(indices)<=MAX_LINKS or not valid_interface_indices(indices,len(indices)):
        raise ValueError(f'Choose {MIN_LINKS} to {MAX_LINKS} different links')
    links = discover_links() if links is None else links
    path = Path(config_path)
    original = path.read_bytes()
    config = json.loads(original)
    chosen = []
    for index in indices:
        row = next((r for r in links if r['index']==index),None)
        if not row:raise ValueError('The selected adapter is no longer listed; refresh the networks')
        usable=bool(row['up'] and row['addresses'] and row['gateway'])
        identity=row.get('id','')
        if not usable and not (isinstance(identity,str) and len(identity)==38 and identity.startswith('{') and identity.endswith('}')):
            raise ValueError('An offline adapter needs a stable Windows adapter identifier')
        chosen.append(row)
    if any(not (r['up'] and r['addresses'] and r['gateway']) for r in chosen):
        ids=[r.get('id','') for r in chosen]
        if not stable_adapter_ids(ids,len(indices)):
            raise ValueError('Refresh the adapters to obtain stable identities before saving an offline link')
    present_ids=[row.get('id','').casefold() for row in chosen if row.get('id')]
    if len(set(present_ids))!=len(present_ids):raise ValueError('Choose different physical adapters')
    live_sources=[row['addresses'][0] for row in chosen if row['up'] and row['addresses'] and row['gateway']]
    if len(set(live_sources))!=len(live_sources) and not stable_adapter_ids([row.get('id','') for row in chosen],len(indices)):
        raise ValueError('Matching IPv4 addresses require distinct stable adapter identifiers')
    config['bind'] = [[row['addresses'][0] if row['up'] and row['addresses'] and row['gateway'] else '0.0.0.0',0] for row in chosen]
    config['interface_indices'] = list(indices)
    config['interface_ids'] = [row.get('id','') for row in chosen]
    config['interface_names'] = [row.get('name',f"Adapter {row['index']}") for row in chosen]
    config['gateways'] = [row['gateway'] for row in chosen]
    # Preserve unrelated settings and refuse to overwrite a concurrent edit.
    if path.read_bytes() != original: raise RuntimeError('Configuration changed; try saving again')
    temporary = path.with_name(path.name+'.widget-'+secrets.token_hex(4))
    try:
        temporary.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
        from .atomic_io import replace_file
        replace_file(temporary,path)
    finally:
        if temporary.exists(): temporary.unlink()
    return config


class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.links = []
        self.rates = {}
        self.error = None
        self.telemetry = None
        self.telemetry_at = 0
        self.owner_pid = None
        self.state = 'offline'
        self.history = deque(maxlen=60)
        self.started = time.monotonic()
        for target in (self._inventory,self._counters,self._telemetry):
            threading.Thread(target=target,daemon=True).start()

    def snapshot(self):
        with self.lock:
            fresh = (self.state=='running' and self.telemetry is not None and
                     time.monotonic()-self.telemetry_at < 7)
            return dict(links=list(self.links),rates=dict(self.rates),error=self.error,
                        state=self.state,telemetry=self.telemetry if fresh else None,
                        telemetry_stale=self.state=='running' and not fresh)

    def _inventory(self):
        while not self.stop.is_set():
            try:
                links = discover_links()
                with self.lock: self.links,self.error = links,None
            except Exception as exc:
                with self.lock: self.error = str(exc)
            self.stop.wait(12)

    def _counters(self):
        sampler = RateSampler()
        while not self.stop.is_set():
            try:
                counters = psutil.net_io_counters(pernic=True,nowrap=True)
                rates = sampler.sample({n:(v.bytes_recv,v.bytes_sent) for n,v in counters.items()},time.monotonic())
                statuses = psutil.net_if_stats()
                for name,row in rates.items():
                    if name not in statuses or not statuses[name].isup:
                        row['down']=row['up']=0
                with self.lock: self.rates = rates
            except Exception as exc:
                with self.lock: self.error = str(exc)
            self.stop.wait(1)

    def _telemetry(self):
        from .tty_server import connect, control, read_metadata
        from .userspace import live_status
        while not self.stop.is_set():
            try:
                runtime=live_status()
                if runtime:
                    with self.lock:
                        self.state,self.owner_pid=runtime['state'],runtime['pid']
                        self.telemetry,self.telemetry_at=runtime,time.monotonic()
                    self.stop.wait(1)
                    continue
                status = control('status',timeout=1,output=io.StringIO())
                pid = status.get('owner_pid')
                state = status.get('state','offline')
                if not pid or not psutil.pid_exists(pid): state='offline'
                with self.lock:
                    self.state,self.owner_pid = state,pid
                    self.telemetry = None
                if state != 'running':
                    self.stop.wait(2)
                    continue
                # No replay: retained records from a stopped test cannot look live.
                with connect(read_metadata(),'attach',tail=0) as sock:
                    sock.settimeout(.5)
                    buffer = bytearray()
                    checked = time.monotonic()
                    while not self.stop.is_set():
                        if time.monotonic()-checked > 3:
                            current=control('status',timeout=1,output=io.StringIO())
                            if current.get('owner_pid')!=pid or current.get('state')!='running': break
                            checked=time.monotonic()
                        try: data=sock.recv(32768)
                        except TimeoutError: continue
                        if not data: break
                        buffer.extend(data)
                        if len(buffer)>1024*1024: raise ValueError('Telemetry record exceeds limit')
                        while b'\n' in buffer:
                            line,_,rest=buffer.partition(b'\n'); buffer=bytearray(rest)
                            try: row=json.loads(line)
                            except ValueError: continue
                            if isinstance(row,dict) and 'transport' in row and row.get('pid')==pid:
                                with self.lock: self.telemetry,self.telemetry_at=row,time.monotonic()
            except (OSError,ValueError,ConnectionError,TimeoutError):
                with self.lock: self.state,self.telemetry='offline',None
                self.stop.wait(2)


def human_bytes(value):
    for unit in ('B','KB','MB','GB','TB'):
        if value < 1024 or unit=='TB': return f'{value:.1f} {unit}'
        value /= 1024
