"""Validated link roles, wire-rate pacing, and persistent billing-cycle usage."""
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import calendar
import json
import math
import os
from pathlib import Path
import secrets
import struct

ROLES=('primary','secondary','backup','never')
POLICY_HEADER=struct.Struct('!QBBdd')
POLICY_ACK_HEADER=struct.Struct('!QQQQ')


def validate_state(state):
    if not isinstance(state,dict) or set(state)!= {'role','blocked','upload_mbps','download_mbps'}:
        raise ValueError('Invalid link policy state')
    if type(state['blocked']) is not bool:raise ValueError('Invalid link policy block flag')
    LinkPolicy(role=state['role'],upload_mbps=state['upload_mbps'],download_mbps=state['download_mbps'])
    return dict(state)


def operational_state(policy,usage):
    result=policy.effective(usage)
    return {key:result[key] for key in ('role','blocked','upload_mbps','download_mbps')}


def encode_state(revision,state):
    state=validate_state(state)
    return POLICY_HEADER.pack(revision,ROLES.index(state['role']),int(state['blocked']),state['upload_mbps'],state['download_mbps'])


def decode_state(payload):
    revision,role,blocked,upload,download=POLICY_HEADER.unpack(payload)
    if role>=len(ROLES) or blocked>1:raise ValueError('Invalid link policy enum')
    return revision,validate_state(dict(role=ROLES[role],blocked=bool(blocked),upload_mbps=upload,download_mbps=download))


@dataclass(frozen=True)
class LinkPolicy:
    role: str = 'primary'
    upload_mbps: float = 0
    download_mbps: float = 0
    daily_bytes: int = 0
    monthly_bytes: int = 0
    reset_day: int = 1
    overlimit: str = 'stop'
    overlimit_mbps: float = .2

    def __post_init__(self):
        if self.role not in ('primary','secondary','backup','never'):raise ValueError('Invalid link role')
        for value in (self.upload_mbps,self.download_mbps,self.overlimit_mbps):
            if type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=10000:
                raise ValueError('Link rates must be finite values from 0 to 10000 Mbps')
        for value in (self.daily_bytes,self.monthly_bytes):
            if type(value) is not int or not 0<=value<=10**16:raise ValueError('Invalid link data cap')
        if type(self.reset_day) is not int or not 1<=self.reset_day<=31:raise ValueError('Billing reset day must be 1..31')
        if self.overlimit not in ('stop','throttle'):raise ValueError('Invalid overlimit behavior')
        if self.overlimit=='throttle' and not self.overlimit_mbps:raise ValueError('Overlimit throttle must be positive')

    def effective(self,usage):
        reached=((self.daily_bytes and usage['daily_bytes']>=self.daily_bytes) or
                 (self.monthly_bytes and usage['monthly_bytes']>=self.monthly_bytes))
        blocked=self.role=='never' or bool(reached and self.overlimit=='stop')
        rates=[self.upload_mbps,self.download_mbps]
        if reached and self.overlimit=='throttle':
            rates=[min(r,self.overlimit_mbps) if r else self.overlimit_mbps for r in rates]
        return dict(role=self.role,blocked=blocked,cap_reached=bool(reached),upload_mbps=rates[0],download_mbps=rates[1])

    def to_dict(self):return asdict(self)


def cycle_start(day,reset_day):
    current=day.replace(day=min(reset_day,calendar.monthrange(day.year,day.month)[1]))
    if day>=current:return current
    previous=day.replace(day=1)-timedelta(days=1)
    return previous.replace(day=min(reset_day,calendar.monthrange(previous.year,previous.month)[1]))


def eligible_roles(candidates,boost=False):
    """Candidates carry health and effective policy; probes are separate."""
    available=[p for p in candidates if p['healthy'] and not p['policy']['blocked']]
    primary=[p for p in available if p['policy']['role']=='primary']
    secondary=[p for p in available if p['policy']['role']=='secondary']
    if primary:return primary+secondary if boost else primary
    if secondary:return secondary
    return [p for p in available if p['policy']['role']=='backup']


class WirePacer:
    """Strict configured wire-byte ceiling, with a bounded packet burst."""
    def __init__(self,rate_mbps=0,burst_bytes=2800):
        self.rate=0.;self.finish=0.;self.burst=burst_bytes
        self.set_rate(rate_mbps,0)

    def set_rate(self,rate_mbps,now):
        if type(rate_mbps) not in (int,float) or not math.isfinite(rate_mbps) or not 0<=rate_mbps<=10000:
            raise ValueError('Invalid configured wire rate')
        rate=rate_mbps*125000
        debt=max(0.,self.finish-now)*self.rate
        self.rate=rate;self.finish=now+debt/rate if rate else now

    def ready_at(self,size,now):
        return now if not self.rate else max(now,self.finish+(size-max(self.burst,size))/self.rate)

    def sent(self,size,now):
        if self.rate:self.finish=max(now,self.finish)+size/self.rate


class UsageLedger:
    """Daily wire bytes survive reconnects; monthly totals use the billing day."""
    def __init__(self,path,clock=None):
        self.path=Path(path);self.clock=clock or (lambda:datetime.now().astimezone())
        self.links={};self.dirty=False
        if self.path.exists():
            if self.path.stat().st_size>4*1024*1024:raise ValueError('Usage ledger exceeds its size limit')
            record=json.loads(self.path.read_text())
            if record.get('version')!=1:raise ValueError('Unsupported usage ledger')
            self.links=record['links']
            if not isinstance(self.links,dict) or len(self.links)>64:raise ValueError('Invalid usage ledger')
            for buckets in self.links.values():
                if not isinstance(buckets,dict) or len(buckets)>400:raise ValueError('Invalid usage history')
                for day,counts in buckets.items():
                    datetime.fromisoformat(day)
                    if set(counts)!= {'upload','download'} or any(type(n) is not int or n<0 for n in counts.values()):
                        raise ValueError('Invalid usage counters')

    def add(self,key,upload=0,download=0):
        if any(type(n) is not int or n<0 for n in (upload,download)):raise ValueError('Usage increments must be nonnegative bytes')
        key=str(key)
        if key not in self.links and len(self.links)>=64:raise ValueError('Too many metered links')
        buckets=self.links.setdefault(key,{})
        today=self.clock().date().isoformat()
        counts=buckets.setdefault(today,dict(upload=0,download=0))
        counts['upload']+=upload;counts['download']+=download
        for expired in sorted(buckets)[:-400]:del buckets[expired]
        self.dirty=True

    def usage(self,key,policy):
        today=self.clock().date();start=cycle_start(today,policy.reset_day).isoformat();end=today.isoformat()
        buckets=self.links.get(str(key),{})
        daily=sum(buckets.get(end,{}).values())
        monthly=sum(sum(value.values()) for day,value in buckets.items() if start<=day<=end)
        return dict(daily_bytes=daily,monthly_bytes=monthly,cycle_start=start)

    def save(self):
        if not self.dirty:return
        self.path.parent.mkdir(parents=True,exist_ok=True)
        temporary=self.path.with_name(self.path.name+'.'+secrets.token_hex(4)+'.tmp')
        try:
            with temporary.open('w') as stream:
                json.dump(dict(version=1,links=self.links),stream);stream.flush();os.fsync(stream.fileno())
            from .atomic_io import replace_file
            replace_file(temporary,self.path);self.dirty=False
        finally:
            if temporary.exists():temporary.unlink()
