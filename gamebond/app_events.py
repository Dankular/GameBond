"""New-app events backed by capture-owner identity and successful tunnel I/O.

Never infer tunnel usage from a process list, an allowlist, or destination-only
correlation. The native capture engine preserves PID/birth time through SOCKS;
the Go stack emits activity only after TCP connect or an actual UDP reply.
"""
from collections import OrderedDict
import json
import ntpath
import os
from pathlib import Path
import secrets
import threading
import time

import psutil
from .atomic_io import replace_file

FILETIME_UNIX_EPOCH = 116444736000000000


def resolve_process(pid, created_filetime):
    """Bind a live executable to its native-captured PID generation."""
    if type(pid) is not int or pid<=0:return None
    try:
        birth=int(created_filetime)
        if birth<=FILETIME_UNIX_EPOCH:return None
        expected=(birth-FILETIME_UNIX_EPOCH)/10_000_000
        process=psutil.Process(pid)
        with process.oneshot():
            created=process.create_time()
            if abs(created-expected)>.001:return None
            path=process.exe();name=process.name()
        if not path or len(path)>32768 or not ntpath.isabs(path):return None
        return dict(pid=pid,created_at=created,created_filetime=str(birth),path=ntpath.normpath(path),name=name)
    except (ValueError,TypeError,OSError,psutil.Error):return None


class AppEventStore:
    """Bounded persistent first-use ledger; reads never replay toasts implicitly."""
    def __init__(self,path,*,resolver=resolve_process,clock=time.time,app_limit=4096,event_limit=256):
        if not 1<=app_limit<=4096 or not 1<=event_limit<=256:raise ValueError('Invalid application history limits')
        self.path=Path(path);self.resolver=resolver;self.clock=clock
        self.app_limit=app_limit;self.event_limit=event_limit
        self.lock=threading.RLock();self.known=OrderedDict();self.events=[];self.sequence=0
        self.unresolved=0;self.rejected=0;self.dirty=False
        self.processes=OrderedDict();self.traffic=OrderedDict();self.skipped_metric_identities=0;self.authorized_owners=OrderedDict()
        if self.path.exists():
            if self.path.stat().st_size>4*1024*1024:raise ValueError('Application event history is too large')
            record=json.loads(self.path.read_text(encoding='utf-8'))
            if record.get('version')!=1:raise ValueError('Unsupported application event history')
            known=record.get('applications',[]);events=record.get('events',[])
            if not isinstance(known,list) or len(known)>app_limit or not isinstance(events,list) or len(events)>event_limit:
                raise ValueError('Invalid application history bounds')
            self.sequence=record.get('sequence',0)
            if type(self.sequence) is not int or self.sequence<0:raise ValueError('Invalid application history sequence')
            for row in known:
                if not isinstance(row,dict) or not isinstance(row.get('path'),str) or not ntpath.isabs(row['path']):
                    raise ValueError('Invalid application identity history')
                self.known[row['path'].casefold()]=row
            last=0
            for event in events:
                if (not isinstance(event,dict) or type(event.get('id')) is not int or not last<event['id']<=self.sequence
                        or event.get('kind')!='new_app_tunnel_use' or not isinstance(event.get('application'),dict)):
                    raise ValueError('Invalid application event history')
                last=event['id']
            self.events=events

    def observe(self,record):
        """Accept metadata produced after identity-authenticated tunnel success."""
        if (not isinstance(record,dict) or record.get('type')!='app_activity' or
                record.get('proof') not in ('tcp_connect','udp_reply') or
                record.get('protocol') not in ('tcp','udp') or
                not isinstance(record.get('destination'),str) or len(record['destination'])>512 or
                type(record.get('pid')) is not int or record['pid']<=0 or
                not isinstance(record.get('created_filetime'),str) or not record['created_filetime'].isdecimal() or
                len(record['created_filetime'])>20):
            with self.lock:self.rejected+=1
            return None
        if (record['proof']=='tcp_connect')!=(record['protocol']=='tcp'):
            with self.lock:self.rejected+=1
            return None
        identity=self.resolver(record.get('pid'),record.get('created_filetime'))
        if not identity:
            with self.lock:
                cached=self.authorized_owners.get((record['pid'],record['created_filetime']))
                if cached and self.clock()-cached[1]<=30:identity=dict(cached[0])
        if not identity:
            with self.lock:self.unresolved+=1
            return None
        key=identity['path'].casefold();now=self.clock()
        with self.lock:
            process_key=(identity['pid'],identity['created_filetime'])
            self.processes[process_key]=dict(identity);self.processes.move_to_end(process_key)
            while len(self.processes)>512:self.processes.popitem(last=False)
            previous=self.known.pop(key,None)
            if previous:
                if now-previous['last_seen']>=60:previous['last_seen']=now;self.dirty=True
                self.known[key]=previous
                return None
            self.known[key]=dict(path=identity['path'],name=identity['name'],first_seen=now,last_seen=now)
            while len(self.known)>self.app_limit:self.known.popitem(last=False)
            self.sequence+=1
            event=dict(id=self.sequence,kind='new_app_tunnel_use',timestamp=now,application=identity,
                       protocol=record['protocol'],destination=record['destination'],proof=record['proof'],
                       attribution='native_capture_owner_and_tunnel_success')
            self.events.append(event);del self.events[:-self.event_limit];self.dirty=True
            return dict(event)

    def remember_authorized_owner(self,identity):
        """Preserve a verified owner if its process exits while connect completes."""
        if not identity:return
        with self.lock:
            key=(identity['pid'],identity['created_filetime'])
            self.authorized_owners[key]=(dict(identity),self.clock());self.authorized_owners.move_to_end(key)
            while len(self.authorized_owners)>512:self.authorized_owners.popitem(last=False)

    def record_usage(self,record):
        """Only enrich counters for identities already proven by a success event."""
        rows=record.get('applications') if isinstance(record,dict) else None
        if not isinstance(record,dict) or record.get('type')!='app_metrics' or not isinstance(rows,list) or len(rows)>64:
            with self.lock:self.rejected+=1
            return
        with self.lock:
            skipped=record.get('skipped_identities',0)
            if type(skipped) is int and skipped>=0:self.skipped_metric_identities=max(self.skipped_metric_identities,skipped)
            for row in rows:
                if not isinstance(row,dict):self.rejected+=1;continue
                pid,birth=row.get('pid'),row.get('created_filetime')
                if type(pid) is not int or not isinstance(birth,str):self.rejected+=1;continue
                key=(pid,birth);identity=self.processes.get(key)
                if identity is None:continue
                fields=('uploaded_bytes','downloaded_bytes','active_connections','generation')
                if any(type(row.get(name)) is not int or row[name]<0 for name in fields):self.rejected+=1;continue
                destinations=row.get('destinations',[])
                if not isinstance(destinations,list) or len(destinations)>8 or any(not isinstance(d,str) or len(d)>512 for d in destinations):
                    self.rejected+=1;continue
                previous=self.traffic.pop(key,None)
                old=(previous if previous and previous['generation']==row['generation'] else {})
                delta_up=max(0,row['uploaded_bytes']-old.get('uploaded_bytes',0))
                delta_down=max(0,row['downloaded_bytes']-old.get('downloaded_bytes',0))
                self.traffic[key]={**identity,**{name:row[name] for name in fields},'destinations':list(destinations),
                                   'last_activity':row.get('last_activity',self.clock())}
                while len(self.traffic)>512:self.traffic.popitem(last=False)
                known=self.known.get(identity['path'].casefold())
                if known and (delta_up or delta_down):
                    known['uploaded_bytes']=known.get('uploaded_bytes',0)+delta_up
                    known['downloaded_bytes']=known.get('downloaded_bytes',0)+delta_down
                    known['last_seen']=self.clock();self.dirty=True

    def traffic_snapshot(self,limit=128):
        with self.lock:
            rows=[dict(row) for row in self.traffic.values()][-min(512,max(1,limit)):]
            while len(json.dumps(rows).encode('utf-8'))>256*1024 and rows:rows.pop(0)
            totals=[dict(row) for row in list(self.known.values())[-128:]]
            while len(json.dumps(totals).encode('utf-8'))>64*1024 and totals:totals.pop(0)
            return dict(rows=rows,tracked_processes=len(self.traffic),truncated=len(rows)<len(self.traffic),
                        skipped_identities=self.skipped_metric_identities,scope='current_tunnel_session',
                        known_totals=totals)

    def snapshot(self,after=0,limit=32):
        with self.lock:
            selected=[dict(row) for row in self.events if row['id']>after]
            count=min(256,max(0,limit))
            selected=selected[-count:] if count else []
            while len(json.dumps(selected).encode('utf-8'))>64*1024 and selected:selected.pop(0)
            return dict(latest_id=self.sequence,events=selected,
                        retained_from=self.events[0]['id'] if self.events else None,
                        known_applications=len(self.known),unresolved_identities=self.unresolved,rejected_events=self.rejected)

    def flush(self):
        with self.lock:
            if not self.dirty:return
            self.path.parent.mkdir(parents=True,exist_ok=True)
            temporary=self.path.with_name(self.path.name+'.'+secrets.token_hex(4)+'.tmp')
            try:
                def encoded():return json.dumps(dict(version=1,sequence=self.sequence,applications=list(self.known.values()),events=self.events))
                payload=encoded()
                while len(payload.encode('utf-8'))>4*1024*1024 and (self.known or self.events):
                    if self.known:self.known.popitem(last=False)
                    if self.events:self.events.pop(0)
                    payload=encoded()
                with temporary.open('w',encoding='utf-8') as stream:
                    stream.write(payload)
                    stream.flush();os.fsync(stream.fileno())
                replace_file(temporary,self.path);self.dirty=False
            finally:
                if temporary.exists():temporary.unlink()
