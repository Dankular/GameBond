"""Generate deterministic Go compatibility vectors from Python PathBudget.

Pure simulated monotonic time. No sockets, routes, live clients or VPS access.
"""
import heapq
import gzip
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from gamebond.bonding import PathBudget

class Trace:
    def __init__(self,name,initial=1,maximum=30):
        self.b=PathBudget(initial,maximum);self.row=dict(name=name,initial=initial,maximum=maximum,operations=[])
    def call(self,method,*args):
        result=getattr(self.b,method)(*args)
        op=dict(method=method,args=list(args),result=result)
        if len(self.row['operations'])%700==0:op['stats']=self.b.stats()
        self.row['operations'].append(op)
        return result
    def finish(self):
        self.row['operations'][-1]['stats']=self.b.stats();return self.row

def busy(name,delay=.04,drop=0,priority=False):
    trace=Trace(name);q=[];sequence=0;counter=0;latest=None;last_ack=0;last_counter=0
    for tick in range(5001):
        now=tick/1000
        while q and q[0][0]<=now:
            at,seq,size=heapq.heappop(q);counter+=size;latest=(seq,at)
        if latest and counter>last_counter and now-last_ack>=.02:
            trace.call('acknowledge',latest[0],counter,now,min(1000000,int((now-latest[1])*1e6)))
            last_counter=counter;last_ack=now
        if priority and tick%10==0:
            trace.call('priority_sent',350,now);sequence+=1
        if tick%100==0:
            trace.call('control_sent',85,now);sequence+=1
        for _ in range(16):
            ready=trace.call('ready_at',1085,now)
            if ready>now:
                trace.call('record_pacing_wait',now,min(ready,now+.001));break
            sequence+=1;trace.call('sent',sequence,1085,now)
            if not drop or sequence%drop:heapq.heappush(q,(now+(delay if now<2 else delay*2),sequence,1085))
    trace.call('expire',8.)
    return trace.finish()

def sparse():
    t=Trace('application_limited_with_invalid_feedback');counter=0
    for i in range(50):
        now=i*.1;t.call('ready_at',1085,now);t.call('sent',i,1085,now);counter+=1085
        t.call('acknowledge',i,counter,now+.04,10000)
        t.call('acknowledge',i,counter+999999,now+.05,0)
    return t.finish()

def bounded():
    t=Trace('pending_capacity_and_timeout_recovery',1000,1000)
    for i in range(4100):t.call('sent',i,1000,.001)
    t.call('ready_at',1000,.1);t.call('expire',.3)
    t.call('acknowledge',4099,4100000,.4,0)
    t.call('sent',4100,1000,.5);t.call('acknowledge',4100,4101000,.55,0)
    t.call('priority_sent',65535,.56);t.call('priority_sent',65535,.56)
    return t.finish()

def congestion():
    t=Trace('corroborated_loss_reduces_rate',4,4);t.call('sent',0,1000,0.);t.call('acknowledge',0,1000,.05,0)
    sequence=1;counter=1000;now=.1
    for _ in range(8):
        count=t.b.window_bytes//1250
        for _ in range(count):t.call('sent',sequence,1250,now);sequence+=1
        t.call('ready_at',1250,now);now+=.2;counter+=int(count*.6)*1250
        assert t.call('acknowledge',sequence-1,counter,now,0)
    assert t.b.stats()['backoffs']>0
    t.call('sent',sequence,1200,3.);t.call('sent',sequence+1,1200,3.001);t.call('expire',5.1)
    return t.finish()

def main():
    rows=[busy('healthy_full_backlog'),busy('slow_feedback_and_expiry',delay=.2),
        busy('settled_loss_with_window_pressure',delay=.08,drop=7),busy('mixed_priority_and_bulk',priority=True),sparse(),bounded(),congestion()]
    target=ROOT/'native-edge/bond/testdata/budget-vectors.json.gz';target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(gzip.compress((json.dumps(rows,separators=(',',':'))+'\n').encode(),mtime=0))
    print(json.dumps(dict(traces=len(rows),operations=sum(len(r['operations']) for r in rows),bytes=target.stat().st_size,
        final=[dict(name=r['name'],rate_mbps=r['operations'][-1]['stats']['rate_mbps'],backoffs=r['operations'][-1]['stats']['backoffs']) for r in rows])))

if __name__=='__main__':main()
