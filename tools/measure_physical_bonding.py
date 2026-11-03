"""Useful TCP payload, each actual adapter alone then both, isolated VPS namespace."""
import argparse
import json
from pathlib import Path
import secrets
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from gamebond.userspace import available_link_config,live_status
from gamebond.windows_adapters import discover_adapters
from stack_peer import StackPeer

def measure(case,seconds,batch,direction='download',outer='udp',candidate_path='.runtime/outer-stage/candidate.json'):
    candidate=json.loads((ROOT/candidate_path).read_text());original=json.loads((ROOT/'configs/local-client.json').read_text())
    config,missing=available_link_config(original,discover_adapters())
    chosen=[int(index) for index in case]
    if any(not config['path_availability'][index] for index in chosen):raise RuntimeError('A requested physical link has no usable current address')
    options={}
    if outer!='udp':options['outer_transport']=dict(endpoints=[dict(mode=outer,port=candidate['tls_port'] if outer!='tcp' else candidate['tcp_port'],
        ca_file=candidate['ca_file'],server_name=candidate['peer'][0])],fallback_after=.1,recovery_interval=300)
    node=Node((ROOT/original['key_file']).read_bytes(),'client',bytes.fromhex(candidate['session']),
        [tuple(config['bind'][i]) for i in chosen],tuple(candidate['peer']),interface_indices=[config['interface_indices'][i] for i in chosen],
        bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,initial_rate_mbps=1,max_rate_mbps=100,**options)
    if outer!='udp':
        from check_outer_wan import BlockUDP
        for carrier in node._sockets:
            if hasattr(carrier,'raw'):carrier.raw=BlockUDP(carrier.raw)
    node.start()
    stack=None;run_id=secrets.token_hex(6)
    try:
        deadline=time.monotonic()+8
        while not all(p['healthy'] for p in node.stats()['paths']):
            if time.monotonic()>deadline:raise RuntimeError('Physical path authentication failed')
            time.sleep(.05)
        stack=StackPeer(node,'physical-'+case,batch=batch)
        with stack.connect('10.77.0.1',8080) as connection:
            connection.sendall(json.dumps(dict(id=run_id,direction=direction,seconds=seconds)).encode()+b'\n')
            ready=bytearray()
            while not ready.endswith(b'\n'):
                part=connection.recv(1)
                if not part:raise EOFError('Benchmark closed before readiness')
                ready.extend(part)
            if json.loads(ready)!=dict(ready=True):raise RuntimeError('Benchmark not ready')
            import psutil
            helper_cpu=psutil.Process(stack.child.pid).cpu_times();started_cpu=time.process_time()
            start=time.perf_counter();received=0;bins=[0]*(seconds+10)
            if direction=='download':
                while True:
                    data=connection.recv(65536);stamp=time.perf_counter()-start
                    if not data:break
                    if data.count(b'Z')!=len(data):raise RuntimeError('Download integrity failed')
                    received+=len(data);bins[min(len(bins)-1,int(stamp))]+=len(data)
            else:
                import socket
                chunk=b'U'*65536
                while time.perf_counter()-start<seconds:
                    connection.sendall(chunk);stamp=time.perf_counter()-start
                    received+=len(chunk);bins[min(len(bins)-1,int(stamp))]+=len(chunk)
                connection.shutdown(socket.SHUT_WR)
                answer=bytearray()
                while not answer.endswith(b'\n'):
                    part=connection.recv(1024)
                    if not part:raise EOFError('Benchmark closed before upload confirmation')
                    answer.extend(part)
                assert json.loads(answer)['received_bytes']==received
            elapsed=time.perf_counter()-start
        assert not stack.errors,stack.errors
        final_helper_cpu=psutil.Process(stack.child.pid).cpu_times()
        warmup=min(4,seconds//3)
        return dict(id=run_id,case=case,direction=direction,batch=batch,outer=outer,seconds=elapsed,requested_seconds=seconds,
            payload_bytes=received,payload_mbps=received*8/elapsed/1e6,steady_payload_mbps=sum(bins[warmup:seconds])*8/(seconds-warmup)/1e6,
            one_second_payload_bytes=bins,ipc=dict(stack.metrics),client=node.stats(),interfaces=[config['interface_indices'][i] for i in chosen],
            parent_cpu_seconds=time.process_time()-started_cpu,
            stack_cpu_seconds=final_helper_cpu.user+final_helper_cpu.system-helper_cpu.user-helper_cpu.system,
            duration_complete=elapsed>=seconds*.95)
    finally:
        if stack:stack.close()
        node.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--seconds',type=int,default=12)
    parser.add_argument('--cases',default='0,1,01');parser.add_argument('--batch',type=int,default=1)
    parser.add_argument('--direction',choices=('download','upload'),default='download')
    parser.add_argument('--outer',choices=('udp','tls','https','tcp'),default='udp')
    parser.add_argument('--candidate',default='.runtime/outer-stage/candidate.json')
    parser.add_argument('--output',default='evidence/physical-bonding-current.json');args=parser.parse_args()
    if not 3<=args.seconds<=25 or not 1<=args.batch<=64:raise ValueError('Invalid benchmark bounds')
    cases=args.cases.split(',')
    if any(case not in ('0','1','01') for case in cases):raise ValueError('Invalid physical selection')
    production=live_status();candidate=json.loads((ROOT/args.candidate).read_text());report=dict(scope='Actual physical adapters to isolated VPS; single TCP stream, useful payload only',
        concurrent_user_traffic_possible=True,results=[],candidate={key:candidate[key] for key in ('container','id','image','tuning') if key in candidate},server_snapshots=[])
    try:
        for case in cases:
            before=None
            if candidate['container'].startswith('gamebond-native-'):
                from native_candidate_snapshot import snapshot
                before=snapshot(args.candidate)
            result=measure(case,args.seconds,args.batch,args.direction,args.outer,args.candidate);report['results'].append(result)
            if before:
                after=snapshot(args.candidate);report['server_snapshots'].append(dict(case=case,before=before,after=after,
                    daemon_cpu_seconds=after['daemon']['cpu_seconds']-before['daemon']['cpu_seconds'],
                    observation_seconds=after['observed_at']-before['observed_at']))
            print(json.dumps({key:result[key] for key in ('id','case','direction','payload_mbps','steady_payload_mbps','ipc')}),flush=True)
        if len(set(cases))==3:
            values={case:statistics.median(row['steady_payload_mbps'] for row in report['results'] if row['case']==case) for case in set(cases)}
            report['bonded_gain_over_best']=values['01']/max(values['0'],values['1'])
            report['passed_aggregation']=report['bonded_gain_over_best']>1.15 and all(r['duration_complete'] for r in report['results'])
        current=live_status()
        if production:assert current and current['pid']==production['pid'],'Production client changed'
        report['production_client_unchanged']=True
    finally:(ROOT/args.output).write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
