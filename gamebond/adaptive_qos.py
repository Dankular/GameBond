"""Explicit app/flow QoS with measured, bounded redundancy and recovery hysteresis.

No packet-size/port heuristic promotes general QUIC to interactive traffic.
The three internal DSCP markers also teach the peer's bidirectional flow cache.
"""
from collections import Counter
from dataclasses import dataclass
import math
import threading
import time

from .policy import Classification,QueuePolicy

PROFILE_TAGS={'bulk':0,'stream':18,'call':26,'game':46}
TAG_PROFILES={value:key for key,value in PROFILE_TAGS.items() if value}

@dataclass(frozen=True)
class QoSSettings:
    enabled:bool=True
    loss_threshold:float=.02
    jitter_threshold_ms:float=8
    recovery_seconds:float=3
    call_deadline_ms:float=60
    stream_deadline_ms:float=120
    game_deadline_ms:float=20
    duplicate_mbps:float=4

    def __post_init__(self):
        if type(self.enabled) is not bool:raise ValueError('QoS enabled must be a boolean')
        for name in ('loss_threshold','jitter_threshold_ms','recovery_seconds','call_deadline_ms','stream_deadline_ms','game_deadline_ms','duplicate_mbps'):
            value=getattr(self,name)
            if type(value) not in (int,float) or not math.isfinite(value) or value<=0:raise ValueError('Invalid QoS '+name)
        if not 0<self.loss_threshold<=1 or self.recovery_seconds>60 or self.duplicate_mbps>1000:raise ValueError('QoS settings out of range')
        if any(not 1<=getattr(self,name)<=2000 for name in ('call_deadline_ms','stream_deadline_ms','game_deadline_ms')):raise ValueError('QoS deadline must be 1..2000ms')

def profile_policies(settings=None):
    settings=settings or QoSSettings()
    return {18:QueuePolicy(True,False,settings.stream_deadline_ms,256),
            26:QueuePolicy(True,False,settings.call_deadline_ms,128),
            46:QueuePolicy(True,True,settings.game_deadline_ms,128)}

def mark_dscp(packet,tag):
    """Mark IPv4 while preserving ECN and all transport bytes/checksums."""
    if packet[0]>>4!=4:raise ValueError('Profile marking requires IPv4')
    if packet[1]>>2==tag:return packet
    data=bytearray(packet);data[1]=(tag<<2)|(data[1]&3);data[10:12]=b'\0\0'
    length=(data[0]&15)*4
    if length<20 or length>len(data):raise ValueError('Invalid IP header')
    checksum=sum((data[i]<<8)|data[i+1] for i in range(0,length,2))
    while checksum>>16:checksum=(checksum&65535)+(checksum>>16)
    data[10:12]=((~checksum)&65535).to_bytes(2,'big')
    return bytes(data)

class AdaptiveQoS:
    def __init__(self,settings=None,*,clock=time.monotonic):
        self.settings=settings or QoSSettings();self.clock=clock;self.lock=threading.RLock()
        self.policies=profile_policies(self.settings);self.policies[0]=QueuePolicy()
        self.last_refresh=-math.inf;self.previous={};self.samples=0;self.healthy=0
        self.quality=[];self.redundancy_until={'call':-math.inf,'stream':-math.inf}
        self.reasons={'call':[],'stream':[]};self.counts=Counter()
        self.tokens=2800.;self.last_token=clock()

    def refresh(self,transport):
        """One quality observation per half-second, never a full stats call per packet."""
        now=self.clock()
        with self.lock:
            if now-self.last_refresh<.5:return
            self.last_refresh=now
        snapshot=transport() if callable(transport) else transport
        self.observe(snapshot,now)

    def observe(self,snapshot,now=None):
        now=self.clock() if now is None else now
        with self.lock:
            quality=[];previous={}
            for ordinal,path in enumerate(snapshot.get('paths',[])[:64]):
                key=(path.get('slot',ordinal),str(path.get('local')),str(path.get('remote')))
                budget=path.get('bonding') or {}
                probes=path.get('probe_quality') or {}
                totals=(budget.get('expired_packets',0),budget.get('acked_packets',0),probes.get('lost',0),probes.get('acked',0),budget.get('delivered_bytes',0))
                old=self.previous.get(key,totals);previous[key]=totals
                expired=max(0,totals[0]-old[0]);acked=max(0,totals[1]-old[1])
                lost_probes=max(0,totals[2]-old[2]);ack_probes=max(0,totals[3]-old[3])
                timeout_ratio=expired/max(1,expired+acked)
                probe_loss=lost_probes/max(1,lost_probes+ack_probes)
                tx_loss=max(0,min(1,budget.get('settled_loss_ratio',0))) if totals[4]>old[4] else 0
                loss=max(tx_loss,probe_loss)
                rtt=path.get('rtt_ms');jitter=path.get('rtt_jitter_ms',0) or 0
                healthy=bool(path.get('available',True) and path.get('enabled',True) and path.get('healthy'))
                if healthy:
                    quality.append(dict(slot=path.get('slot',ordinal),loss=loss,tx_ack_loss=tx_loss,feedback_timeout_ratio=timeout_ratio,round_trip_probe_loss=probe_loss,jitter_ms=jitter,
                        predicted_ms=(rtt/2 if rtt is not None else 1000)+2*jitter+max(0,budget.get('queue_delay_ms',0))))
            self.previous=previous;self.quality=quality;self.healthy=len(quality);self.samples+=1
            for profile,deadline in (('call',self.settings.call_deadline_ms),('stream',self.settings.stream_deadline_ms)):
                reasons=[]
                if len(quality)>1:
                    best=min(quality,key=lambda q:q['predicted_ms'])
                    if best['loss']>=self.settings.loss_threshold:reasons.append('measured_loss')
                    if best['feedback_timeout_ratio']>=self.settings.loss_threshold:reasons.append('feedback_timeout')
                    if best['jitter_ms']>=self.settings.jitter_threshold_ms:reasons.append('jitter')
                    if best['predicted_ms']>=deadline*.75:reasons.append('deadline_risk')
                if reasons:self.redundancy_until[profile]=now+self.settings.recovery_seconds
                self.reasons[profile]=reasons or (['recovery_hold'] if now<self.redundancy_until[profile] else [])

    def classify(self,classification,profile=None):
        if not self.settings.enabled:return classification
        if profile=='automatic':profile=None
        profile=profile or TAG_PROFILES.get(classification.dscp)
        if profile is None:return classification
        if profile not in PROFILE_TAGS:raise ValueError('Unknown flow profile')
        with self.lock:
            self.counts['classified_'+profile]+=1
            policy=self.policies[PROFILE_TAGS[profile]]
            return Classification(classification.info,PROFILE_TAGS[profile],policy,'app_profile_'+profile)

    def transmission(self,classification,size):
        """Decide duplication at dequeue time so expired quality is not baked into queues."""
        if not self.settings.enabled:return classification.policy.priority,classification.policy.replicate
        profile=TAG_PROFILES.get(classification.dscp)
        urgent=classification.policy.priority;replicate=classification.policy.replicate
        now=self.clock()
        with self.lock:
            if profile in ('call','stream'):
                replicate=self.healthy>1 and now<self.redundancy_until[profile]
                if replicate:
                    rate=self.settings.duplicate_mbps*1_000_000/8
                    # The overhead budget charges every additional encrypted copy.
                    extra=(size+128)*max(1,self.healthy-1)
                    self.tokens=min(2800.,self.tokens+max(0,now-self.last_token)*rate);self.last_token=now
                    if self.tokens>=extra:self.tokens-=extra
                    else:replicate=False;self.counts['duplicate_budget_limited']+=1
            self.counts['replicated' if replicate else 'single']+=1
        return urgent,replicate

    def stats(self):
        with self.lock:
            now=self.clock()
            return dict(enabled=self.settings.enabled,quality_samples=self.samples,healthy_paths=self.healthy,
                path_quality=list(self.quality),redundancy={p:dict(active=self.healthy>1 and now<until,
                reason=list(self.reasons[p]),hold_remaining_ms=max(0,(until-now)*1000)) for p,until in self.redundancy_until.items()},
                counters=dict(self.counts),duplicate_budget_mbps=self.settings.duplicate_mbps)
