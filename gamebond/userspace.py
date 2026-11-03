"""Persistent non-elevated GameBond runtime: ProxiFyre -> netstack -> VPS.

Captures all resolvable applications or a configured executable list, excluding
the tunnel's own carrier. Windows routes, adapters, DNS and QoS are untouched.
The already installed Windows Packet Filter driver must be accessible.
"""
from __future__ import annotations
import argparse
import ctypes
import hmac
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import OrderedDict,deque
from concurrent.futures import ThreadPoolExecutor
import ipaddress

import psutil

from .app import load_config
from .policy import Classifier, PriorityScheduler, QueuePolicy,is_tcp_control
from .transport import Node, OVERHEAD, BOND_OVERHEAD
from .capture import proxy_configuration
from .link_policy import LinkPolicy, UsageLedger, operational_state
from .app_events import AppEventStore,resolve_process
from .adaptive_qos import AdaptiveQoS,QoSSettings,profile_policies,mark_dscp
from .atomic_io import replace_file,read_json_shared

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/'.runtime'
STATUS=RUNTIME/'userspace-status.json'
CONTROL=RUNTIME/'userspace-control.json'
HIDDEN=getattr(subprocess,'CREATE_NO_WINDOW',0)


def atomic_json(path,value):
    temporary=path.with_name(path.name+'.tmp-'+secrets.token_hex(4))
    try:
        temporary.write_text(json.dumps(value),encoding='utf-8')
        replace_file(temporary,path)
    finally:
        try:temporary.unlink(missing_ok=True)
        except OSError:pass


def live_status():
    try:
        if STATUS.stat().st_size>1024*1024:return None
        data=read_json_shared(STATUS,1024*1024)
        if time.time()-data['updated_at']>5:return None
        process=psutil.Process(data['pid'])
        if abs(process.create_time()-data['created'])>.01:return None
        if data['state'] not in ('starting','connecting','running','stopping'):return None
        return data
    except (OSError,ValueError,KeyError,psutil.Error):return None


def request_stop():
    status=live_status()
    if not status:return
    record=read_json_shared(CONTROL,16384)
    if record['pid']!=status['pid']:raise RuntimeError('Tunnel controller changed; retry')
    with socket.create_connection(('127.0.0.1',record['port']),timeout=2) as sock:
        sock.sendall(json.dumps({'token':record['token'],'command':'stop'}).encode()+b'\n')
        if json.loads(sock.recv(1024)).get('ok') is not True:raise RuntimeError('Stop request rejected')


def mark_game_udp(packet, game_ports=None):
    """Explicit selected-process UDP policy, preserving ECN and IP checksum."""
    if len(packet)<20 or packet[0]>>4!=4 or packet[9]!=17:return packet
    header_length=(packet[0]&15)*4
    if header_length<20 or header_length>len(packet):raise ValueError('Invalid IPv4 header')
    if game_ports is not None:
        if len(packet)<header_length+8:return packet
        source,destination=struct.unpack_from('!HH',packet,header_length)
        if source not in game_ports and destination not in game_ports:return packet
    data=bytearray(packet);data[1]=(46<<2)|(data[1]&3);data[10:12]=b'\0\0'
    words=struct.unpack('!'+('H'*(header_length//2)),data[:header_length])
    checksum=sum(words)
    while checksum>>16:checksum=(checksum&65535)+(checksum>>16)
    data[10:12]=struct.pack('!H',(~checksum)&65535)
    return bytes(data)


def read_exact(stream,size):
    result=bytearray()
    while len(result)<size:
        part=stream.read(size-len(result))
        if not part:raise EOFError('Network stack exited')
        result.extend(part)
    return bytes(result)


def preflight():
    if live_status():raise RuntimeError('GameBond is already running')
    recover_owned_children()
    for process in psutil.process_iter(['name']):
        if (process.info['name'] or '').lower()=='proxifyre.exe':
            raise RuntimeError('Another ProxiFyre instance is active. Stop it first.')
    if psutil.win_service_get('ProxiFyreService').status()=='running':
        raise RuntimeError('The ProxiFyre service is active. Stop it first.')


def available_link_config(config, links, *, require_available=True):
    """Resolve selected physical adapters at startup without changing saved choices."""
    selected={row['index']:row for row in links}
    identities={str(row.get('id','')).lower():row for row in links if row.get('id')}
    active=[];unavailable=[];available=[];ids=[]
    for position,index in enumerate(config['interface_indices']):
        identity=(config.get('interface_ids') or ['']*len(config['interface_indices']))[position]
        row=identities.get(identity.lower()) if identity else selected.get(index)
        ids.append(identity or (row or {}).get('id',''))
        addresses=[] if not row else [ip for ip in row.get('addresses',[])
            if not ipaddress.IPv4Address(ip).is_link_local and not ipaddress.IPv4Address(ip).is_unspecified]
        if not row or not row.get('up') or not addresses or not row.get('gateway'):
            unavailable.append(dict(interface_index=index,name=(row or {}).get('name',str(index)),
                                    reason='No usable IPv4 address and gateway on the selected adapter'))
            active.append(((row or {}).get('index',index),['0.0.0.0',0],''));available.append(False)
            continue
        saved=config['bind'][position][0]
        active.append((index,[saved if saved in addresses else addresses[0],config['bind'][position][1]],row['gateway']))
        active[-1]=(row['index'],active[-1][1],active[-1][2]);available.append(True)
    if require_available and not any(available):
        raise RuntimeError('No selected network is available. Connect Starlink or enable phone USB tethering, then retry.')
    resolved=dict(config)
    resolved.update(interface_indices=[r[0] for r in active],bind=[r[1] for r in active],gateways=[r[2] for r in active],
                    path_availability=available,interface_ids=ids)
    return resolved,unavailable


def recover_owned_children():
    try:previous=read_json_shared(STATUS,1024*1024)
    except (OSError,ValueError):return
    try:
        owner=psutil.Process(previous['pid'])
        if abs(owner.create_time()-previous['created'])<.01:
            raise RuntimeError('An existing GameBond runtime is unresponsive; wait for it to stop')
    except psutil.NoSuchProcess:pass
    expected={str((RUNTIME/'userspace-proxy/ProxiFyre.exe').resolve()).casefold(),
              str((ROOT/'build/gamebond-netstack-attribution.exe').resolve()).casefold(),
              str((ROOT/'build/gamebond-netstack-metrics.exe').resolve()).casefold(),
              str((ROOT/'build/gamebond-netstack.exe').resolve()).casefold()}
    for process in psutil.process_iter(['exe','ppid','create_time']):
        try:
            info=process.info
            if (info['ppid']==previous['pid'] and (info['exe'] or '').casefold() in expected and
                    previous['created']<=info['create_time']<=previous['updated_at']+2):
                process.terminate();process.wait(timeout=3)
        except (psutil.NoSuchProcess,psutil.AccessDenied):pass


class Runtime:
    def __init__(self,config,key,config_path=None):
        self.config,self.key=config,key
        self.selected_config=dict(config);self.policy_keys=[str(i) for i in config['interface_indices']]
        self.adapter_notifications=None;self.link_inventory_error=None;self.last_link_refresh=0
        self.last_link_snapshot=None
        self.config_path=Path(config_path) if config_path else ROOT/'configs/local-client.json'
        self.stop=threading.Event();self.errors=queue.Queue();self.ready=queue.Queue()
        self.node=None;self.stack=None;self.proxy=None;self.logs=[];self.workers=[]
        attributed=ROOT/'build/gamebond-netstack-attribution.exe'
        candidate=attributed if config.get('app_attribution_enabled',False) and attributed.is_file() else ROOT/'build/gamebond-netstack-metrics.exe'
        self.stack_path=candidate if candidate.is_file() else ROOT/'build/gamebond-netstack.exe'
        self.capture_extension=None;self.capture_token='';self.app_event_error=None
        manifest=ROOT/'build/native-capture/manifest.json';extension=manifest.with_name('socksify.dll')
        if self.stack_path==attributed and manifest.is_file() and extension.is_file():
            record=json.loads(manifest.read_text())
            if (record.get('schema')!=1 or record.get('feature')!='gamebond-owner-v1' or
                    hashlib.sha256(extension.read_bytes()).hexdigest()!=record.get('dll_sha256')):
                raise ValueError('Native application attribution build integrity check failed')
            self.capture_extension=extension;self.capture_token=secrets.token_hex(32)
        try:self.app_events=AppEventStore(RUNTIME/'app-history.json')
        except (ValueError,OSError,KeyError,TypeError) as exc:self.app_events=None;self.app_event_error=str(exc)
        self.stack_write_lock=threading.Lock();self.authorization_slots=threading.BoundedSemaphore(64)
        self.authorization_workers=ThreadPoolExecutor(max_workers=4,thread_name_prefix='gamebond-app-policy')
        self.authorization_counts=dict(allowed=0,denied=0,errors=0);self.authorization_decisions=deque(maxlen=32)
        self.authorization_lock=threading.Lock();self.flow_profiles=OrderedDict()
        from .app_policy import PolicyEvaluator
        self.policy_lock=threading.Lock();self.policy_stamp=None;self.application_policy=PolicyEvaluator(config)
        self.application_policy_state=self.policy_snapshot()
        self.last_transport={}
        self.application_bytes=None
        self.usage_ledger=UsageLedger(RUNTIME/'link-usage.json')
        self.previous_wire={};self.link_usage={}
        self.link_policies={str(index):LinkPolicy(**config.get('link_policies',{}).get(str(index),{}))
                            for index in config['interface_indices']}
        from .process_job import ProcessJob
        self.job=ProcessJob()
        self.scheduler=PriorityScheduler(capacity=1024)
        self.qos=AdaptiveQoS(QoSSettings(**config.get('adaptive_qos',{})))
        policies=profile_policies(self.qos.settings) if self.qos.settings.enabled else {}
        policies.update({int(k):QueuePolicy(**v) for k,v in config.get('queues',{}).items()})
        self.classifier=Classifier(policies)
        self.created=psutil.Process().create_time();self.token=secrets.token_hex(32)
        self.state='starting';self.error=None
        self.configured_links=len(config['interface_indices']);self.unavailable_links=[]
        self.counts=dict(tagged_game_udp=0,bulk_enqueued=0,malformed=0,injected=0)
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(4);self.listener.settimeout(.2)
        atomic_json(CONTROL,dict(pid=os.getpid(),port=self.listener.getsockname()[1],token=self.token))

    def publish(self):
        if self.node:
            try:self.last_transport=self.node.stats()
            except OSError:pass
            self.meter_links()
        if self.app_events:
            try:self.app_events.flush()
            except OSError as exc:self.app_event_error=str(exc)
        app_traffic=self.app_events.traffic_snapshot() if self.app_events else None
        atomic_json(STATUS,dict(pid=os.getpid(),created=self.created,updated_at=time.time(),
            state=self.state,error=self.error,peer=self.config['peer'],backend='userspace',
            capture_mode=self.config.get('capture_mode','all'),captured_apps=self.config.get('cod_executables',[]),
            configured_links=self.configured_links,unavailable_links=self.unavailable_links,
            waiting_for_network=not any(self.config.get('path_availability',[True])),
            link_inventory_error=self.link_inventory_error,
            application=self.application_bytes,
            app_attribution=dict(available=self.capture_extension is not None,history_error=self.app_event_error,
                                 source='native_capture_owner_and_tunnel_success' if self.capture_extension else None),
            app_events=self.app_events.snapshot() if self.app_events else None,
            applications=app_traffic['rows'] if app_traffic else [],
            application_traffic={key:value for key,value in app_traffic.items() if key!='rows'} if app_traffic else None,
            app_authorization=self.authorization_snapshot(),
            application_policy=self.application_policy_state,
            link_usage=self.link_usage,
            qos=self.qos.stats(),transport=self.last_transport,packets=dict(self.counts)))

    def meter_links(self):
        for path in self.last_transport.get('paths',[]):
            slot=path.get('slot')
            key=self.policy_keys[slot] if slot is not None and hasattr(self,'policy_keys') else str(path.get('interface_index'))
            if key not in self.link_policies:continue
            current=(path.get('wire_tx_bytes',path['tx_bytes']),path.get('metered_download_bytes',path['rx_bytes']))
            previous=self.previous_wire.get(key,(0,0))
            upload,download=[max(0,value-old) for value,old in zip(current,previous)]
            if upload or download:self.usage_ledger.add(key,upload,download)
            self.previous_wire[key]=current
        self.usage_ledger.save()
        self.link_usage={key:{**self.usage_ledger.usage(key,policy),**policy.effective(self.usage_ledger.usage(key,policy))}
                         for key,policy in self.link_policies.items()}
        if 'link_policies' in self.config:
            self.node.set_link_states([operational_state(self.link_policies[str(index)],self.link_usage[str(index)])
                                       for index in getattr(self,'policy_keys',self.config['interface_indices'])])

    def refresh_links(self,initial=False):
        if os.name!='nt':return
        if not initial and time.monotonic()-self.last_link_refresh<1 and not (self.adapter_notifications and self.adapter_notifications.changed.is_set()):return
        self.last_link_refresh=time.monotonic()
        if self.adapter_notifications:self.adapter_notifications.changed.clear()
        from .windows_adapters import discover_adapters
        try:
            resolved,missing=available_link_config(self.selected_config,discover_adapters(),require_available=False)
            self.selected_config['interface_ids']=resolved['interface_ids']
            if initial:
                # Persist stable adapter IDs once; IP addresses remain observations.
                try:
                    original=self.config_path.read_bytes();saved=json.loads(original)
                    if saved.get('interface_indices')==self.selected_config['interface_indices'] and not saved.get('interface_ids'):
                        saved['interface_ids']=resolved['interface_ids']
                        if self.config_path.read_bytes()==original:atomic_json(self.config_path,saved)
                except (OSError,ValueError):pass
            errors=self.node.update_client_paths([tuple(b) for b in resolved['bind']],resolved['interface_indices'],resolved['path_availability']) if self.node else []
            self.config=resolved;self.unavailable_links=missing
            self.link_inventory_error='; '.join(e['error'] for e in errors) or None
            snapshot=[dict(interface_id=identity,interface_index=index,address=bind[0],available=live)
                      for identity,index,bind,live in zip(resolved['interface_ids'],resolved['interface_indices'],resolved['bind'],resolved['path_availability'])]
            if snapshot!=self.last_link_snapshot:
                print(json.dumps(dict(status='physical_links_changed',links=snapshot,unavailable_links=missing)),flush=True)
                self.last_link_snapshot=snapshot
        except (OSError,ValueError,RuntimeError) as exc:
            if initial:raise
            self.link_inventory_error=str(exc)

    def policy_snapshot(self):
        snapshot=self.application_policy.snapshot()
        snapshot['policy_digest']=hashlib.sha256(json.dumps(snapshot,sort_keys=True).encode()).hexdigest()
        snapshot['rules_total']=len(snapshot['rules']);snapshot['rules_truncated']=False
        bounded={};size=0
        for key,value in snapshot['rules'].items():
            size+=len(json.dumps({key:value}).encode('utf-8'))
            if size>96*1024:snapshot['rules_truncated']=True;break
            bounded[key]=value
        snapshot['rules']=bounded
        return {**snapshot,'applies_to':'new_outbound_connections','existing_connections':'reconnect_to_apply'}

    def authorization_snapshot(self):
        with self.authorization_lock:
            recent=list(self.authorization_decisions)
            while len(json.dumps(recent).encode('utf-8'))>32*1024 and recent:recent.pop(0)
            return {**self.authorization_counts,'recent':recent}

    def worker(self,function):
        def run():
            try:function()
            except Exception as exc:
                if not self.stop.is_set():self.errors.put(str(exc));self.stop.set()
        thread=threading.Thread(target=run,daemon=True);thread.start();self.workers.append(thread)

    def controller(self):
        while not self.stop.is_set():
            try:connection,_=self.listener.accept()
            except socket.timeout:continue
            with connection:
                connection.settimeout(1);data=bytearray()
                try:
                    while b'\n' not in data and len(data)<=4096:
                        chunk=connection.recv(1024)
                        if not chunk:break
                        data.extend(chunk)
                    request=json.loads(data)
                    valid=request.get('command')=='stop' and hmac.compare_digest(str(request.get('token','')),self.token)
                    connection.sendall(json.dumps({'ok':valid}).encode())
                    if valid:self.stop.set()
                except (OSError,ValueError):pass

    def read_stack(self):
        while not self.stop.is_set():
            kind,size=struct.unpack('!BH',read_exact(self.stack.stdout,3))
            # Control JSON (notably app metrics) can exceed the IP MTU.
            # Only packet frames are limited to 1280 bytes by this stack.
            if not size or (kind==0 and size>1280):raise ValueError('Invalid stack packet size')
            packet=read_exact(self.stack.stdout,size)
            if kind==2:
                record=json.loads(packet)
                if record.get('type')=='application_metrics':self.application_bytes=record
                elif record.get('type')=='app_activity':
                    if self.app_events and self.capture_extension:self.app_events.observe(record)
                elif record.get('type')=='app_metrics':
                    if self.app_events and self.capture_extension:self.app_events.record_usage(record)
                elif record.get('type')=='app_authorization_request':self.queue_authorization(record)
                elif record.get('type')=='app_flow_profile':self.observe_flow_profile(record)
                elif isinstance(record.get('socks'),str):self.ready.put(record)
                else:self.counts['malformed']+=1
                continue
            if kind!=0:raise ValueError('Unexpected stack endpoint')
            try:
                packet=mark_game_udp(packet,self.config.get('game_udp_ports',[]))
                classification=self.classifier.classify(packet)
                self.qos.refresh(self.node.stats)
                record=self.flow_profiles.get(classification.info.flow)
                if record and time.monotonic()-record['last_seen']>120:
                    self.flow_profiles.pop(classification.info.flow,None);record=None
                if record:record['last_seen']=time.monotonic()
                classification=self.qos.classify(classification,record['profile'] if record else None)
                if record and self.qos.settings.enabled:packet=mark_dscp(packet,classification.dscp)
            except ValueError:
                self.counts['malformed']+=1;continue
            if classification.policy.priority or is_tcp_control(packet):
                if classification.dscp==46 and classification.info.protocol==17:self.counts['tagged_game_udp']+=1
                self.counts['direct_priority_packets']=self.counts.get('direct_priority_packets',0)+1
                urgent,replicate=self.qos.transmission(classification,len(packet))
                urgent=urgent or is_tcp_control(packet)
                self.node.send(packet,replicate=replicate,flow_id=classification.info.flow,urgent=urgent)
            elif self.scheduler.push(packet,classification):self.counts['bulk_enqueued']+=1

    def send_bulk(self):
        while not self.stop.is_set():
            item=self.scheduler.pop(.1)
            if item:
                urgent,replicate=self.qos.transmission(item.classification,len(item.packet))
                self.node.send(item.packet,replicate=replicate,flow_id=item.classification.info.flow,urgent=urgent)

    def receive(self):
        while not self.stop.is_set():
            try:packet=self.node.recv(.1)
            except queue.Empty:continue
            self.write_stack_frame(0,packet)
            self.counts['injected']+=1

    def write_stack_frame(self,kind,packet):
        with self.stack_write_lock:
            self.stack.stdin.write(struct.pack('!BH',kind,len(packet))+packet);self.stack.stdin.flush()

    def queue_authorization(self,record):
        request_id=record.get('id')
        if not isinstance(request_id,str) or len(request_id)!=24 or any(c not in '0123456789abcdef' for c in request_id):return
        if not self.capture_extension or not self.authorization_slots.acquire(blocking=False):
            self.write_stack_frame(3,json.dumps(dict(type='app_authorization_response',id=request_id,allow=False,profile='bulk')).encode());return
        try:self.authorization_workers.submit(self.authorize_application,record)
        except RuntimeError:self.authorization_slots.release()

    def authorize_application(self,record):
        decision=dict(allow=False,profile='bulk',reason='authorization_failed');identity=None
        try:
            from .app_policy import PolicyEvaluator,MAX_CONFIG_BYTES
            identity=resolve_process(record.get('pid'),record.get('created_filetime'))
            with self.policy_lock:
                if self.config_path.is_file():
                    stat=self.config_path.stat();stamp=(stat.st_mtime_ns,stat.st_size)
                    if stat.st_size>MAX_CONFIG_BYTES:raise ValueError('Application policy configuration is too large')
                    if stamp!=self.policy_stamp:
                        config=json.loads(self.config_path.read_text(encoding='utf-8'))
                        self.application_policy=PolicyEvaluator(config);self.policy_stamp=stamp
                        self.application_policy_state=self.policy_snapshot()
                evaluator=self.application_policy
            decision=evaluator.authorize(identity,record.get('protocol'),record.get('destination'))
            if type(decision.get('allow')) is not bool or decision.get('profile') not in ('automatic','bulk','game','call','stream'):
                raise ValueError('Invalid application policy decision')
            if identity and decision['allow'] and self.app_events:self.app_events.remember_authorized_owner(identity)
        except Exception:
            decision=dict(allow=False,profile='bulk',reason='authorization_failed')
            with self.authorization_lock:self.authorization_counts['errors']+=1
        try:
            with self.authorization_lock:
                self.authorization_counts['allowed' if decision['allow'] else 'denied']+=1
                self.authorization_decisions.append(dict(timestamp=time.time(),application=identity,
                    captured_pid=record.get('pid'),captured_created_filetime=record.get('created_filetime'),
                    protocol=record.get('protocol'),destination=record.get('destination'),**decision))
            self.write_stack_frame(3,json.dumps(dict(type='app_authorization_response',id=record['id'],
                allow=decision['allow'],profile=decision['profile'])).encode())
        except (OSError,ValueError):pass
        finally:self.authorization_slots.release()

    def observe_flow_profile(self,record):
        if record.get('profile') not in ('automatic','bulk','game','call','stream') or record.get('protocol') not in ('tcp','udp'):return
        try:
            source,source_port=record['source'].rsplit(':',1);destination,destination_port=record['destination'].rsplit(':',1)
            source=ipaddress.ip_address(source);destination=ipaddress.ip_address(destination)
            source_port=int(source_port);destination_port=int(destination_port)
            if str(source)!=self.config['client_tunnel_ip'] or not 1<=source_port<=65535 or not 1<=destination_port<=65535:return
            endpoints=sorted(((source.packed,source_port),(destination.packed,destination_port)))
            key=(source.version,6 if record['protocol']=='tcp' else 17,*endpoints)
            self.flow_profiles[key]=dict(profile=record['profile'],pid=record.get('pid'),created_filetime=record.get('created_filetime'),last_seen=time.monotonic())
            self.flow_profiles.move_to_end(key)
            while len(self.flow_profiles)>4096:self.flow_profiles.popitem(last=False)
        except (ValueError,KeyError,TypeError):return

    def stage_proxy(self,address):
        directory=RUNTIME/'userspace-proxy';directory.mkdir(exist_ok=True)
        source=Path('C:/Program Files/ProxiFyre')
        for name in ('ProxiFyre.exe','ProxiFyre.exe.config','ProxiFyre.Configuration.dll',
                     'Newtonsoft.Json.dll','NLog.dll','NLog.config','socksify.dll','Topshelf.dll'):
            shutil.copy2(source/name,directory/name)
        if self.capture_extension:shutil.copy2(self.capture_extension,directory/'socksify.dll')
        probe=ROOT/'build/gamebond-internet-probe.exe'
        shutil.copy2(self.stack_path,probe)
        configuration=proxy_configuration(self.config,address,ROOT,netstack_executable=self.stack_path)
        if self.capture_extension:
            for proxy in configuration['proxies']:
                proxy['username']='gamebond-attribution-v1';proxy['password']=self.capture_token
        atomic_json(directory/'app-config.json',configuration)
        log=directory/'logs/logfile.txt'
        if log.exists():log.write_text('')
        output=(directory/'console.txt').open('w');self.logs.append(output)
        self.proxy=subprocess.Popen([str(directory/'ProxiFyre.exe'),'--allow-not-admin'],cwd=directory,
                                    stdout=output,stderr=subprocess.STDOUT,creationflags=HIDDEN)
        self.job.add(self.proxy)
        deadline=time.monotonic()+8
        while time.monotonic()<deadline and not self.stop.wait(.1):
            if self.proxy.poll() is not None:raise RuntimeError('ProxiFyre could not start; check .runtime/userspace-proxy/console.txt')
            if log.exists() and 'ProxiFyre Service is running' in log.read_text(errors='replace'):return
        raise RuntimeError('Application capture did not become ready')

    def run(self):
        self.publish();self.worker(self.controller)
        try:
            config=self.config
            if os.name=='nt':
                from .windows_adapters import AdapterNotifications
                self.refresh_links(initial=True)
                self.adapter_notifications=AdapterNotifications()
                config=self.config
            self.node=Node(self.key,'client',bytes.fromhex(config['session']),[tuple(b) for b in config['bind']],
                tuple(config['peer']),interface_indices=config['interface_indices'],bonding_mode=True,
                mtu=config.get('mtu',1280)+OVERHEAD+BOND_OVERHEAD,
                initial_rate_mbps=config.get('bonding_initial_rate_mbps',1),
                max_rate_mbps=config.get('bonding_max_rate_mbps',100),
                link_states=([operational_state(self.link_policies[str(index)],self.usage_ledger.usage(str(index),self.link_policies[str(index)]))
                             for index in self.policy_keys] if 'link_policies' in config else None),
                path_availability=config.get('path_availability'),outer_transport=config.get('outer_transport')).start()
            self.state='connecting';self.publish()
            deadline=time.monotonic()+12
            heartbeat=0
            while time.monotonic()<deadline and not self.stop.wait(.1):
                self.refresh_links()
                if not any(self.config.get('path_availability',[True])):deadline=time.monotonic()+12
                if time.monotonic()-heartbeat>=1:self.publish();heartbeat=time.monotonic()
                paths=self.node.stats()['paths']
                if any(p['healthy'] for p in paths):break
            else:
                if self.stop.is_set():return
                if any(p.get('ready') and not p.get('policy_confirmed',True) for p in paths):
                    raise RuntimeError('Your VPS has not acknowledged link policies; update the server before using link controls')
                if all(not p.get('enabled',True) for p in paths):
                    raise RuntimeError('All selected links are disabled or have reached their data cap')
                raise RuntimeError('Neither selected link could authenticate with your VPS')
            errors=(RUNTIME/'netstack-runtime.log').open('w');self.logs.append(errors)
            stack_environment=os.environ.copy();stack_environment.pop('GAMEBOND_CAPTURE_TOKEN',None)
            if self.capture_extension:stack_environment['GAMEBOND_CAPTURE_TOKEN']=self.capture_token
            if self.capture_extension:stack_environment['GAMEBOND_APP_AUTHORIZATION']='1'
            else:stack_environment.pop('GAMEBOND_APP_AUTHORIZATION',None)
            self.stack=subprocess.Popen([str(self.stack_path),'--proxy-stdio'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,creationflags=HIDDEN,env=stack_environment)
            self.job.add(self.stack)
            for worker in (self.read_stack,self.send_bulk,self.receive):self.worker(worker)
            address=self.ready.get(timeout=5)['socks']
            self.stage_proxy(address)
            self.state='running';self.publish()
            while not self.stop.wait(1):
                self.refresh_links()
                if self.stack.poll() is not None or self.proxy.poll() is not None:raise RuntimeError('Network stack or application capture stopped unexpectedly')
                self.publish()
            if not self.errors.empty():raise RuntimeError(self.errors.get())
        except Exception as exc:
            self.error=str(exc);self.state='failed'
        finally:
            if self.adapter_notifications:self.adapter_notifications.close()
            self.stop.set();self.scheduler.close()
            self.authorization_workers.shutdown(wait=True,cancel_futures=True)
            failed=self.state=='failed';self.state='stopping'
            try:self.publish()
            except OSError as exc:print(json.dumps(dict(status='status_write_failed_during_cleanup',error=str(exc))),flush=True)
            for process in (self.proxy,self.stack):
                if process is not None:
                    if process.poll() is None:process.terminate()
                    process.wait(timeout=3)
            self.job.close()
            for thread in self.workers:thread.join(timeout=1)
            if self.node:self.node.close()
            self.listener.close()
            for output in self.logs:output.close()
            if self.stack:
                for stream in (self.stack.stdin,self.stack.stdout):
                    try:stream.close()
                    except OSError:pass  # An exited helper may leave a broken pipe.
            self.state='failed' if failed else 'stopped'
            try:self.publish()
            except OSError as exc:print(json.dumps(dict(status='final_status_write_failed',error=str(exc))),flush=True)
        if self.error:raise RuntimeError(self.error)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default=str(ROOT/'configs/local-client.json'))
    parser.add_argument('--key',default=None)
    args=parser.parse_args();RUNTIME.mkdir(exist_ok=True)
    # A held OS file lock prevents two simultaneous starts without a service.
    import msvcrt
    with (RUNTIME/'userspace.lock').open('a+b') as lock:
        try:
            if lock.seek(0,os.SEEK_END)==0:lock.write(b'0');lock.flush()
            lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
        except OSError as exc:raise RuntimeError('GameBond is already running or another connection is starting. Wait for it to finish.') from exc
        try:
            preflight()
            config=load_config(args.config,allow_unavailable_links=True)
            if not config.get('bonding_mode') or not config.get('direct_priority',True):raise ValueError('Userspace runtime requires bonding and direct priority')
            key_path=Path(args.key or config.get('key_file',str(ROOT/'secrets/gamebond.key')))
            if not key_path.is_absolute():key_path=ROOT/key_path
            Runtime(config,key_path.read_bytes(),config_path=args.config).run()
        except Exception as exc:
            atomic_json(RUNTIME/'userspace-start-error.json',dict(pid=os.getpid(),error=str(exc)))
            raise

if __name__=='__main__':main()
