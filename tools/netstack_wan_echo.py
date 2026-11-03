"""Executed only inside the temporary VPS test container.

The orchestrator supplies KEY and SESSION in memory over authenticated SSH.
All address/link configuration stays in this container's network namespace.
"""
import json
import os
import cProfile
import queue
import signal
import socket
import subprocess
import threading
import time

from gamebond.transport import Node, OVERHEAD, BOND_OVERHEAD
from gamebond.policy import Classifier, QueuePolicy
from gamebond.tun import LinuxTun

stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
threading.Timer(90, stop.set).start()
tun = LinuxTun('gbe2e', 1280)
subprocess.run(['ip','address','add','10.77.0.1/30','dev','gbe2e'], check=True)
subprocess.run(['ip','link','set','dev','gbe2e','mtu','1280','up'], check=True)
node = Node(KEY, 'server', SESSION, [('0.0.0.0',4433)],
            bonding_mode=True, mtu=1280+OVERHEAD+BOND_OVERHEAD,
            initial_rate_mbps=float(os.environ.get('GAMEBOND_TEST_INITIAL_MBPS','1')), max_rate_mbps=100,
            probe_interval=.1, path_timeout=1)
classifier = Classifier({46: QueuePolicy(priority=True, replicate=True)}, game_ports=[8081])
capture_metrics=dict(packets=0,send_seconds=0,send_max_ms=0,read_seconds=0)
capture_profile=cProfile.Profile()

def capture():
    if os.environ.get('GAMEBOND_TEST_PROFILE')=='1':capture_profile.enable()
    while not stop.is_set():
        reading=time.perf_counter()
        packet = tun.read(.1)
        capture_metrics['read_seconds']+=time.perf_counter()-reading
        if packet:
            classification = classifier.classify(packet)
            sending=time.perf_counter()
            node.send(packet, replicate=classification.policy.replicate,
                      flow_id=classification.info.flow)
            elapsed=time.perf_counter()-sending
            capture_metrics['packets']+=1
            capture_metrics['send_seconds']+=elapsed
            capture_metrics['send_max_ms']=max(capture_metrics['send_max_ms'],elapsed*1000)

def inject():
    while not stop.is_set():
        try:
            packet = node.recv(.1)
            # Single synthetic client only. No arbitrary source injection.
            if len(packet) >= 20 and packet[12:16] == socket.inet_aton('10.77.0.2'):
                tun.write(packet)
        except queue.Empty:
            pass

def tcp_echo():
    with socket.socket() as listener:
        listener.bind(('10.77.0.1',8080)); listener.listen(2); listener.settimeout(.2)
        while not stop.is_set():
            try: connection,_ = listener.accept()
            except socket.timeout: continue
            with connection:
                connection.settimeout(10)
                first=connection.recv(65536)
                if first.startswith(b'GBDL1'):
                    seconds=min(20,max(1,int(first[5:].decode('ascii'))))
                    end=time.monotonic()+seconds
                    while time.monotonic()<end and not stop.is_set():
                        connection.sendall(b'Z'*16384)
                    continue
                if first:connection.sendall(first)
                while not stop.is_set():
                    packet = connection.recv(65536)
                    if not packet: break
                    connection.sendall(packet)

def udp_echo():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.bind(('10.77.0.1',8081)); udp.settimeout(.2)
        while not stop.is_set():
            try: packet,peer = udp.recvfrom(2048)
            except socket.timeout: continue
            if peer[0] == '10.77.0.2': udp.sendto(packet,peer)

def guarded(fn):
    def run():
        try: fn()
        except Exception as exc:
            print(json.dumps({'worker_error':repr(exc)}),flush=True)
            stop.set()
    return run

tcp_history=[]
def record(stopping=False):
    result = {'transport':node.stats(),'stopping':stopping,'capture_metrics':dict(capture_metrics)}
    if os.environ.get('GAMEBOND_TEST_PROFILE')=='1':
        result['capture_profile']=[dict(code=str(p.code),calls=p.callcount,seconds=p.inlinetime,total=p.totaltime)
                                   for p in sorted(capture_profile.getstats(),key=lambda p:p.inlinetime,reverse=True)[:20]]
    result['tcp_state']=subprocess.run(['ss','-tin','sport','=',':8080'],capture_output=True,text=True).stdout
    if len(result['tcp_state'].splitlines())>1:
        tcp_history.append(result['tcp_state']);del tcp_history[:-15]
    result['tcp_history']=list(tcp_history)
    with open('/proc/net/snmp') as file:result['network_counters']=file.read()
    with open('/tmp/result.json','w') as file: json.dump(result,file)
    print(json.dumps(result),flush=True)

node.start()
workers = [threading.Thread(target=guarded(fn),daemon=True) for fn in (capture,inject,tcp_echo,udp_echo)]
for thread in workers: thread.start()
print(json.dumps({'ready':True,'scope':'isolated VPS namespace','udp_port':4433}),flush=True)
record()
try:
    while not stop.wait(1):
        record()
finally:
    record(True)
    for thread in workers: thread.join(timeout=1)
    node.close(); tun.close()
