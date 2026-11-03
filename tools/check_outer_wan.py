"""Isolated netstack-to-VPS TCP/UDP egress with the candidate's outer UDP blocked."""
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from gamebond.policy import parse_packet
from gamebond.process_job import ProcessJob
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from gamebond.userspace import available_link_config,live_status
from gamebond.windows_adapters import discover_adapters

def exact(stream,size):
    result=bytearray()
    while len(result)<size:
        part=stream.recv(size-len(result)) if hasattr(stream,'recv') else stream.read(size-len(result))
        if not part:raise EOFError('Test stream closed')
        result.extend(part)
    return bytes(result)

def wait(predicate,seconds=12):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.05)
    raise RuntimeError('Candidate carrier readiness timed out')

class BlockUDP:
    def __init__(self,raw):self.raw=raw;self.blocked=True;self.dropped=0
    def sendto(self,data,endpoint):
        if self.blocked:self.dropped+=1;return len(data)
        return self.raw.sendto(data,endpoint)
    def __getattr__(self,name):return getattr(self.raw,name)
    def fileno(self):return self.raw.fileno()

def socks(address,command,target,port):
    stream=socket.create_connection(address,timeout=8);stream.settimeout(8)
    stream.sendall(b'\x05\x01\x00')
    if exact(stream,2)!=b'\x05\x00':stream.close();raise RuntimeError('SOCKS negotiation failed')
    stream.sendall(bytes([5,command,0,1])+socket.inet_aton(target)+struct.pack('!H',port))
    response=exact(stream,10)
    if response[:4]!=b'\x05\x00\x00\x01':stream.close();raise RuntimeError('SOCKS target rejected')
    return stream,(socket.inet_ntoa(response[4:8]),struct.unpack('!H',response[8:])[0])

def probes(address):
    stream,_=socks(address,1,'1.1.1.1',443)
    with ssl.create_default_context().wrap_socket(stream,server_hostname='1.1.1.1') as secure:
        secure.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
        data=bytearray()
        while len(data)<65536:
            chunk=secure.recv(4096)
            if not chunk:break
            data.extend(chunk)
    match=re.search(rb'(?:^|\n)ip=([0-9.]+)',data)
    if not match or not bytes(data).startswith(b'HTTP/1.1 200'):raise RuntimeError('HTTPS trace failed')
    https=match[1].decode()
    control,relay=socks(address,3,'0.0.0.0',0)
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1',0));udp.settimeout(2)
            query=b'\0\x01\0\0'+bytes.fromhex('2112a442')+secrets.token_bytes(12)
            request=b'\0\0\0\x01'+socket.inet_aton('162.159.207.0')+struct.pack('!H',3478)+query
            for attempt in range(3):
                udp.sendto(request,relay)
                try:answer,_=udp.recvfrom(2048);break
                except socket.timeout:
                    if attempt==2:raise
            answer=answer[10:]
            if len(answer)<20 or answer[:2]!=b'\x01\x01' or answer[4:20]!=query[4:20]:raise RuntimeError('Invalid STUN reply')
            public=None;offset=20
            while offset+4<=len(answer):
                kind,length=struct.unpack_from('!HH',answer,offset);offset+=4
                if offset+length>len(answer):raise RuntimeError('Invalid STUN attribute')
                if kind==0x20 and length==8 and answer[offset+1]==1:
                    public=socket.inet_ntoa(bytes(answer[offset+4+i]^query[4+i] for i in range(4)))
                offset+=(length+3)&~3
            if public!=https:raise RuntimeError('UDP and HTTPS egress differ')
            return dict(https_egress_ipv4=https,udp_egress_ipv4=public)
    finally:control.close()

def check(mode,candidate,config,key):
    endpoint=dict(mode=mode,port=candidate['tcp_port'] if mode=='tcp' else candidate['tls_port'])
    if mode!='tcp':endpoint.update(ca_file=candidate['ca_file'],server_name=candidate['peer'][0])
    node=Node(key,'client',bytes.fromhex(candidate['session']),[tuple(b) for b in config['bind']],tuple(candidate['peer']),
        interface_indices=config['interface_indices'],path_availability=config['path_availability'],bonding_mode=True,
        mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.1,
        outer_transport=dict(endpoints=[endpoint],fallback_after=.3,recovery_interval=1))
    blocked=[]
    for sock in node._sockets:
        if hasattr(sock,'raw'):
            sock.raw=BlockUDP(sock.raw);blocked.append(sock.raw)
    stop=threading.Event();ready=queue.Queue();workers=[];errors=[];helper=None;job=ProcessJob();output=None
    try:
        node.start();wait(lambda:all(p['healthy'] for p in node.stats()['paths'] if p['available']))
        assert all(s.mode==mode for s in node._sockets if hasattr(s,'mode'))
        env=os.environ.copy();env.pop('GAMEBOND_CAPTURE_TOKEN',None);env.pop('GAMEBOND_APP_AUTHORIZATION',None)
        output=(ROOT/'.runtime/outer-stage'/('helper-'+mode+'.log')).open('w')
        helper=subprocess.Popen([str(ROOT/'build/gamebond-netstack-attribution.exe'),'--proxy-stdio'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=output,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
        job.add(helper)
        def read_stack():
            while not stop.is_set():
                kind,size=struct.unpack('!BH',exact(helper.stdout,3));packet=exact(helper.stdout,size)
                if kind==2:
                    record=json.loads(packet)
                    if record.get('socks'):ready.put(record['socks'])
                elif kind==0:node.send(packet,False,parse_packet(packet).flow)
        def write_stack():
            while not stop.is_set():
                try:packet=node.recv(.1)
                except queue.Empty:continue
                helper.stdin.write(struct.pack('!BH',0,len(packet))+packet);helper.stdin.flush()
        def guarded(fn):
            try:fn()
            except (OSError,EOFError,ValueError) as exc:
                if not stop.is_set():errors.append(str(exc));stop.set()
        for fn in (read_stack,write_stack):
            worker=threading.Thread(target=guarded,args=(fn,),daemon=True);worker.start();workers.append(worker)
        host,port=ready.get(timeout=4).rsplit(':',1);address=(host,int(port))
        result=dict(mode=mode,blocked_outer_udp_probes=sum(b.dropped for b in blocked),blocked=probes(address))
        assert result['blocked']['https_egress_ipv4']==candidate['peer'][0]
        assert not errors,errors
        result['fallback_paths']=[p['outer_transport'] for p in node.stats()['paths']]
        # Restore only these test UDP sockets, then prove recovery with the same
        # userspace TCP/IP stack and encrypted session still alive.
        for raw in blocked:raw.blocked=False
        wait(lambda:all(s.mode=='udp' for s in node._sockets if hasattr(s,'mode')))
        result['recovered']=probes(address)
        assert result['recovered']['https_egress_ipv4']==candidate['peer'][0]
        result.update(passed=True,recovery_paths=[p['outer_transport'] for p in node.stats()['paths']])
        return result
    finally:
        stop.set()
        if helper:
            if helper.poll() is None:helper.terminate()
            try:helper.wait(timeout=3)
            finally:job.close()
        else:job.close()
        node.close()
        for worker in workers:worker.join(1)
        if helper:
            for pipe in (helper.stdin,helper.stdout):
                try:pipe.close()
                except OSError:pass
        if output:output.close()

def main():
    candidate=json.loads((ROOT/'.runtime/outer-stage/candidate.json').read_text())
    original=json.loads((ROOT/'configs/local-client.json').read_text())
    config,missing=available_link_config(original,discover_adapters());key=(ROOT/original['key_file']).read_bytes()
    production=live_status();report=dict(scope='Isolated VPS container and netstack; only candidate UDP writes are blackholed',
        candidate=candidate['container'],peer=candidate['peer'],unavailable_links=missing,results=[])
    try:
        for mode in ('tls','https','tcp'):
            result=check(mode,candidate,config,key);report['results'].append(result)
            print(json.dumps(dict(mode=mode,passed=True,blocked=result['blocked'],recovered=result['recovered'])),flush=True)
        current=live_status()
        if production:assert current and current['pid']==production['pid'] and current['state']=='running','Production client changed'
        report['production_client_unchanged']=True;report['passed']=True
    finally:(ROOT/'evidence/outer-fallback-wan.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
