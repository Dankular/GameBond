"""Isolated Linux Docker full-stack probe: real TUN, TCP and UDP, no public ports.

The two simulated uplinks share the VPS bridge. Results measure software overhead
and injected impairment, not independent ISP capacity. Never uses a live session.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve()
def command(*args, **kwargs):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True, **kwargs)

def quantiles(values):
    ordered = sorted(values)
    def at(p):
        return ordered[min(len(ordered)-1, int((len(ordered)-1)*p))] if ordered else None
    return dict(count=len(values), p50=at(.5), p95=at(.95), p99=at(.99), max=max(values, default=None))

def native_server():
    import signal
    process=subprocess.Popen(['/probe-native-edge','--config','/probe/server.json','--key','/probe/key'],
                             env=dict(os.environ,GAMEBOND_NATIVE_EDGE='1'),stdout=subprocess.PIPE,text=True)
    signal.signal(signal.SIGTERM,lambda *_:process.terminate())
    try:
        for line in process.stdout:
            raw=json.loads(line)
            if raw.get('status')=='running':
                command('ip','address','add','10.77.0.1/30','dev','gamebond0')
                command('ip','link','set','gamebond0','mtu','1280','up')
                Path('/tmp/probe-ready').touch()
            if 'queues' not in raw:continue
            q=raw['queues']['transmit'];inject=raw['queues']['inject'];t=raw['transport'];send=t['send'];receive=t['receive']
            fields=Path('/proc/'+str(process.pid)+'/stat').read_text().split(') ',1)[1].split()
            cpu=(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')+time.process_time()
            paths=[dict(healthy=p['Healthy']) for p in t['paths'] or []]
            data=dict(cpu_seconds=cpu,observed_at=time.monotonic(),native_raw=raw,
                      queues=dict(enqueued=q['Admitted'],dequeued=q['Completed'],dropped_stale=q['Expired'],dropped_full=q['Rejected'],residence_ms=dict(count=0,mean=0)),
                      transport=dict(paths=paths,tx_packets=send['PayloadPackets'],rx_packets=receive['PayloadPackets'],
                                     tx_bytes=sum(p['WireTX'] for p in t['paths'] or []),rx_bytes=receive['WireRX'],
                                     socket_errors=send['SocketErrors']+receive['SendErrors'],auth_failures=receive['AuthenticationErrors'],
                                     receive_drops=sum(inject[k] for k in ('Expired','Rejected','EvictedBulk','WriteRejected'))))
            temporary=Path('/tmp/probe-status.tmp');temporary.write_text(json.dumps(data));temporary.replace('/tmp/probe-status.json')
    finally:
        if process.poll() is None:process.terminate()
        process.wait(timeout=5)
    if process.returncode:raise SystemExit(process.returncode)

def child(role, switch_ms, profile=False, retain_io_gil=False):
    from gamebond import app
    if profile:
        import yappi
        yappi.set_clock_type('cpu')
        yappi.start(builtins=True,profile_threads=True)
    if switch_ms:
        sys.setswitchinterval(switch_ms / 1000)
    config = json.loads(Path('/probe/'+role+'.json').read_text())
    nodes, queues = [], []
    node_class, queue_class = app.Node, app.PriorityScheduler
    def node_factory(*args, **kwargs):
        node = node_class(*args, **kwargs)
        if retain_io_gil:
            import ctypes
            libc=ctypes.PyDLL(None,use_errno=True)
            send=libc.sendto;send.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];send.restype=ctypes.c_ssize_t
            receive=libc.recvfrom;receive.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint)];receive.restype=ctypes.c_ssize_t
            class SocketProbe:
                def __init__(self,sock):
                    assert sock.gettimeout()==0.0
                    self.sock=sock;self.buffer=ctypes.create_string_buffer(65536);self.address=ctypes.create_string_buffer(16)
                def __getattr__(self,name):return getattr(self.sock,name)
                def sendto(self,data,endpoint):
                    address=struct.pack('=HH4s8x',socket.AF_INET,socket.htons(endpoint[1]),socket.inet_aton(endpoint[0]))
                    count=send(self.sock.fileno(),data,len(data),socket.MSG_DONTWAIT,address,16)
                    if count<0:
                        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
                    return count
                def recvfrom(self,size):
                    length=ctypes.c_uint(16)
                    count=receive(self.sock.fileno(),self.buffer,min(size,65536),socket.MSG_DONTWAIT,self.address,ctypes.byref(length))
                    if count<0:
                        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
                    address=self.address.raw
                    return ctypes.string_at(self.buffer,count),(socket.inet_ntoa(address[4:8]),struct.unpack_from('!H',address,2)[0])
            node._sockets=[SocketProbe(sock) for sock in node._sockets]
        nodes.append(node); return node
    def queue_factory(*args, **kwargs):
        scheduler = queue_class(*args, **kwargs); queues.append(scheduler); return scheduler
    app.Node, app.PriorityScheduler = node_factory, queue_factory
    stop = threading.Event()
    def ready():
        address = '10.77.0.1/30' if role == 'server' else '10.77.0.2/30'
        command('ip', 'address', 'add', address, 'dev', 'gamebond0')
        command('ip', 'link', 'set', 'gamebond0', 'mtu', '1280', 'up')
        Path('/tmp/probe-ready').touch()
        def sample():
            while not stop.wait(.5):
                try:
                    data = dict(transport=nodes[0].stats(), queues=queues[0].stats())
                    data['cpu_seconds'] = time.process_time()
                    data['observed_at'] = time.monotonic()
                    temporary = Path('/tmp/probe-status.tmp')
                    temporary.write_text(json.dumps(data)); temporary.replace('/tmp/probe-status.json')
                except Exception as exc:
                    Path('/tmp/probe-sampler-error').write_text(str(exc)); return
        threading.Thread(target=sample, daemon=True).start()
    try:
        app.run(config, '/probe/key', stop_event=stop, on_ready=ready)
    finally:
        stop.set()
        if profile:
            yappi.stop()
            functions=[dict(function=f.full_name,calls=f.ncall,self_cpu_seconds=f.tsub,cumulative_cpu_seconds=f.ttot) for f in yappi.get_func_stats()]
            functions.sort(key=lambda f:f['self_cpu_seconds'],reverse=True)
            threads=[dict(name=t.name,id=t.id,cpu_seconds=t.ttot) for t in yappi.get_thread_stats()]
            Path('/results/'+role+'-profile.json').write_text(json.dumps(dict(functions=functions[:40],threads=threads,process_cpu_seconds=time.process_time())))

def service():
    def echo():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('10.77.0.1', 3075))
            while True:
                payload, peer = sock.recvfrom(2048)
                sequence,stamp=struct.unpack('!IQ',payload)
                received=time.perf_counter_ns()
                sock.sendto(struct.pack('!IQQQ',sequence,stamp,received,time.perf_counter_ns()),peer)
    def transfer(connection):
        with connection:
            connection.settimeout(30)
            request = bytearray()
            while not request.endswith(b'\n'):
                part = connection.recv(1)
                if not part or len(request) >= 64:
                    return
                request.extend(part)
            seconds = float(request.decode())
            if not 1 <= seconds <= 30: return
            end = time.monotonic()+seconds
            chunk = b'Z'*65536
            try:
                while time.monotonic()<end: connection.sendall(chunk)
            except OSError: pass
    threading.Thread(target=echo, daemon=True).start()
    with socket.create_server(('10.77.0.1', 18080)) as listener:
        Path('/tmp/probe-service-ready').touch()
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=transfer, args=(connection,), daemon=True).start()

def traffic(seconds, bulk, blackout):
    stop=threading.Event(); records=[]; components=[]; sent=[]; failures=[]; bytes_received=[0]
    started=time.monotonic()
    phases=[]
    def phase(t):
        return 'outage' if blackout and seconds*.35 <= t < seconds*.65 else ('recovery' if blackout and t >= seconds*.65 else 'baseline')
    def download():
        try:
            with socket.create_connection(('10.77.0.1',18080),timeout=5) as conn:
                conn.sendall((str(seconds)+'\n').encode());conn.settimeout(seconds+5)
                while not stop.is_set():
                    data=conn.recv(65536)
                    if not data:break
                    if data.count(b'Z')!=len(data): raise ValueError('TCP payload corruption')
                    bytes_received[0]+=len(data)
        except Exception as exc:failures.append('TCP: '+str(exc))
    def impairment():
        table='stack_probe'
        rules='add table inet '+table+'\nadd chain inet '+table+' output { type filter hook output priority 0; policy accept; }\nadd chain inet '+table+' input { type filter hook input priority 0; policy accept; }\nadd rule inet '+table+' output udp sport 44401 drop\nadd rule inet '+table+' input udp dport 44401 drop\n'
        time.sleep(seconds*.35)
        subprocess.run(['nft','-f','-'],input=rules,text=True,check=True,capture_output=True)
        phases.append(dict(event='outage_started',elapsed=time.monotonic()-started))
        time.sleep(seconds*.3)
        command('nft','delete','table','inet',table)
        phases.append(dict(event='outage_ended',elapsed=time.monotonic()-started))
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.bind(('10.77.0.2',0));udp.settimeout(.05)
        def receive():
            while not stop.is_set():
                try:
                    data=udp.recv(2048)
                    observed=time.perf_counter_ns()
                    sequence,stamp,server_received,server_sent=struct.unpack('!IQQQ',data)
                    records.append((sequence,(observed-stamp)/1e6))
                    components.append(((server_received-stamp)/1e6,(server_sent-server_received)/1e6,(observed-server_sent)/1e6))
                except socket.timeout:pass
                except Exception as exc:
                    failures.append('UDP: '+str(exc));return
        workers=[threading.Thread(target=receive)]
        if bulk:workers.append(threading.Thread(target=download))
        if blackout:workers.append(threading.Thread(target=impairment))
        for worker in workers:worker.start()
        sequence=0
        while time.monotonic()-started<seconds:
            target=started+sequence/60
            delay=target-time.monotonic()
            if delay>0:time.sleep(delay)
            elapsed=time.monotonic()-started
            if elapsed>=seconds:break
            sent.append((sequence,phase(elapsed)))
            udp.sendto(struct.pack('!IQ',sequence,time.perf_counter_ns()),('10.77.0.1',3075))
            sequence+=1
        time.sleep(.5);stop.set()
        for worker in workers:worker.join(5)
    received=dict(records)
    result=dict(seconds=seconds,tcp_bytes=bytes_received[0],tcp_mbps=bytes_received[0]*8/seconds/1e6,
                udp_sent=len(sent),udp_received=len(received),udp_missing=len(sent)-len(received),
                udp_rtt_ms=quantiles([rtt for _,rtt in records]),phases={},events=phases,errors=failures)
    result['udp_segments_ms']={name:quantiles([row[index] for row in components]) for index,name in enumerate(('client_to_server','echo_service','server_to_client'))}
    for name in sorted({p for _,p in sent}):
        ids=[n for n,p in sent if p==name]
        result['phases'][name]=dict(sent=len(ids),missing=sum(n not in received for n in ids),
                                   rtt_ms=quantiles([received[n] for n in ids if n in received]))
    print(json.dumps(result),flush=True)
    if failures or len(received)!=len(sent):raise SystemExit(1)

def controller(args):
    if os.name!='posix':raise SystemExit('Run on the Linux Docker host; no host routes are modified.')
    tag='gb-probe-'+secrets.token_hex(4)
    names=[tag+'-server',tag+'-client']; network=tag
    report=dict(scope=__doc__.strip(),image=args.image,source=args.source,
                switch_ms=args.switch_ms,delay_ms=args.delay_ms,links=args.links,
                seconds=args.seconds,bulk=args.bulk,blackout=args.blackout,retain_io_gil=args.retain_io_gil,native_server=bool(args.native_server))
    with tempfile.TemporaryDirectory(prefix=tag+'-') as directory:
        root=Path(directory);root.chmod(0o700)
        (root/'key').write_bytes(secrets.token_bytes(32));(root/'key').chmod(0o600)
        common=dict(session=secrets.token_hex(16),tun_name='gamebond0',mtu=1280,
                    client_tunnel_ip='10.77.0.2',bonding_mode=True,redundant_mode=False,direct_priority=True,
                    bonding_initial_rate_mbps=10,bonding_max_rate_mbps=100,
                    game_udp_ports=[3075],queues={'0':dict(priority=False,replicate=False,max_age_ms=100,capacity=256),
                                                 '46':dict(priority=True,replicate=True,max_age_ms=20,capacity=128)})
        def docker(*parts):return command('docker',*parts)
        def wait(name,path):
            for _ in range(100):
                state=json.loads(docker('inspect',name))[0]
                if not state['State']['Running']:raise RuntimeError(docker('logs',name)[-3000:])
                if subprocess.run(['docker','exec',name,'test','-e',path],capture_output=True).returncode==0:return
                time.sleep(.1)
            raise RuntimeError('Readiness timed out: '+name)
        try:
            docker('network','create','--internal',network)
            server_ip=None
            for role,name in zip(('server','client'),names):
                c=dict(common,role=role,bind=[['0.0.0.0',4433]] if role=='server' else [['0.0.0.0',44401+i] for i in range(args.links)])
                if role=='client':c['peer']=[server_ip,4433]
                (root/(role+'.json')).write_text(json.dumps(c));(root/(role+'.json')).chmod(0o600)
                options=['run','-d','--name',name,'--label','gamebond.purpose=stack-probe','--network',network,
                         '--cap-drop','ALL','--cap-add','NET_ADMIN','--device','/dev/net/tun','--read-only',
                         '--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
                         '--tmpfs','/tmp:rw,nosuid,size=32m','-v',str(root)+':/probe:ro',
                         '-v',str(HERE)+':/probe-runner.py:ro','--entrypoint','python']
                if args.profile:options+=['-v',str(root)+':/results:rw']
                if role=='server' and args.native_server:options+=['-v',str(Path(args.native_server).resolve())+':/probe-native-edge:ro']
                if args.source:options+=['-v',str(Path(args.source).resolve())+':/work:ro','-e','PYTHONPATH=/work']
                mode='native-server' if role=='server' and args.native_server else role
                options +=[args.image,'-u','/probe-runner.py','--mode',mode,'--switch-ms',str(args.switch_ms)]
                if args.profile:options+=['--profile']
                if args.retain_io_gil:options+=['--retain-io-gil']
                docker(*options);wait(name,'/tmp/probe-ready')
                if role=='server':server_ip=json.loads(docker('inspect',name))[0]['NetworkSettings']['Networks'][network]['IPAddress']
                if args.delay_ms:docker('exec',name,'tc','qdisc','add','dev','eth0','root','netem','delay',str(args.delay_ms)+'ms')
            docker('exec','-d',names[0],'python','/probe-runner.py','--mode','service')
            wait(names[0],'/tmp/probe-service-ready')
            time.sleep(2)
            before={n:json.loads(docker('exec',n,'cat','/tmp/probe-status.json')) for n in names}
            probe=['docker','exec',names[1],'python','/probe-runner.py','--mode','traffic','--seconds',str(args.seconds)]
            if args.bulk:probe+=['--bulk']
            if args.blackout:probe+=['--blackout']
            result=subprocess.run(probe,capture_output=True,text=True,timeout=args.seconds+20)
            if not result.stdout:raise RuntimeError(result.stderr)
            report['traffic']=json.loads(result.stdout);report['traffic_exit_code']=result.returncode
            time.sleep(.6)
            after={n:json.loads(docker('exec',n,'cat','/tmp/probe-status.json')) for n in names}
            for role,name in zip(('server','client'),names):
                a,b=before[name],after[name];qa,qb=a['queues'],b['queues']
                observed_seconds=b['observed_at']-a['observed_at']
                report[role]=dict(observed_seconds=observed_seconds,cpu_seconds=b['cpu_seconds']-a['cpu_seconds'],cpu_cores=(b['cpu_seconds']-a['cpu_seconds'])/observed_seconds,
                                  queues={k:qb.get(k,0)-qa.get(k,0) for k in ['enqueued','dequeued','dropped_stale','dropped_full']},
                                  queue_mean_ms=qb['residence_ms']['mean'],
                                  healthy_links=sum(p['healthy'] for p in b['transport']['paths']),
                                  transport={k:b['transport'].get(k,0)-a['transport'].get(k,0) for k in ['tx_bytes','rx_bytes','socket_errors','auth_failures','receive_drops','bulk_pacing_wait_us','bonding_deadline_drops']})
                count=qb['residence_ms']['count']-qa['residence_ms']['count']
                report[role]['queue_mean_ms']=(qb['residence_ms']['count']*qb['residence_ms']['mean']-qa['residence_ms']['count']*qa['residence_ms']['mean'])/count if count else 0
                payload_packets=sum(b['transport'].get(k,0)-a['transport'].get(k,0) for k in ('tx_packets','rx_packets'))
                report[role]['payload_packets']=payload_packets
                report[role]['cpu_us_per_payload_packet']=report[role]['cpu_seconds']*1e6/max(1,payload_packets)
                if 'native_raw' in b:
                    report[role]['queue_mean_ms']=None
                    report[role]['native_raw']=b['native_raw']
                    report[role]['unsupported_metrics']=['queue_mean_ms','bulk_pacing_wait_us','bonding_deadline_drops']
                    for metric in ('bulk_pacing_wait_us','bonding_deadline_drops'):report[role]['transport'][metric]=None
            if args.profile:
                for name in names:docker('stop','--time','8',name)
                report['cpu_profiles']={}
                for role in ('server','client'):
                    data=json.loads((root/(role+'-profile.json')).read_text())
                    if any(f['self_cpu_seconds']<0 or f['self_cpu_seconds']>f['cumulative_cpu_seconds']+1e-6 for f in data['functions']):
                        raise RuntimeError('Invalid CPU profile measurements')
                    if sum(t['cpu_seconds'] for t in data['threads'])>data['process_cpu_seconds']*1.1:
                        raise RuntimeError('Thread CPU counters exceed process CPU time')
                    report['cpu_profiles'][role]=data
        finally:
            for name in reversed(names):subprocess.run(['docker','rm','-f',name],capture_output=True)
            subprocess.run(['docker','network','rm',network],capture_output=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    report['checks']={'traffic_integrity':report['traffic_exit_code']==0}
    if args.bulk:report['checks']['bulk_progress']=report['traffic']['tcp_bytes']>0
    if args.max_udp_p99_ms is not None:
        latency=report['traffic']['udp_rtt_ms']['p99']
        report['checks']['udp_p99_budget']=latency is not None and latency<=args.max_udp_p99_ms
        report['max_udp_p99_ms']=args.max_udp_p99_ms
    report['passed']=all(report['checks'].values())
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report),flush=True)
    if not report['passed']:raise SystemExit(1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=['controller','server','client','native-server','service','traffic'],default='controller')
    p.add_argument('--image');p.add_argument('--source');p.add_argument('--switch-ms',type=float,default=0)
    p.add_argument('--seconds',type=float,default=10);p.add_argument('--delay-ms',type=float,default=0)
    p.add_argument('--links',type=int,default=2);p.add_argument('--bulk',action='store_true');p.add_argument('--blackout',action='store_true')
    p.add_argument('--profile',action='store_true',help='Collect per-thread CPU profiles; do not compare profiled throughput with unprofiled runs')
    p.add_argument('--retain-io-gil',action='store_true',help='Isolated nonblocking UDP I/O experiment')
    p.add_argument('--native-server',help='Compare the existing Go daemon, mounted into the isolated server container')
    p.add_argument('--max-udp-p99-ms',type=float,help='Fail the full-stack run when game-packet p99 RTT exceeds this budget')
    p.add_argument('--output',type=Path,default=Path('evidence/stack-probe.json'))
    args=p.parse_args()
    if not 1<=args.seconds<=30 or not 1<=args.links<=8 or not 0<=args.delay_ms<=100 or not 0<=args.switch_ms<=10:p.error('Probe bounds exceeded')
    if args.mode=='controller':
        if not args.image:p.error('--image is required')
        controller(args)
    elif args.mode in ('server','client'):child(args.mode,args.switch_ms,args.profile,args.retain_io_gil)
    elif args.mode=='native-server':native_server()
    elif args.mode=='service':service()
    else:traffic(args.seconds,args.bulk,args.blackout)

if __name__=='__main__':main()
