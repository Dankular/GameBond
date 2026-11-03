"""Test-owned userspace stack, no host capture or network configuration changes."""
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import threading
import time
from gamebond.policy import parse_packet
from gamebond.process_job import ProcessJob

ROOT=Path(__file__).resolve().parents[1]

def exact(stream,size):
    result=bytearray()
    while len(result)<size:
        part=stream.read(size-len(result)) if hasattr(stream,'read') else stream.recv(size-len(result))
        if not part:raise EOFError('Stack stream closed')
        result.extend(part)
    return bytes(result)

class StackPeer:
    def __init__(self,node,label='benchmark',batch=1):
        self.node=node;self.stop=threading.Event();self.ready=queue.Queue();self.workers=[];self.errors=[];self.batch=batch
        self.metrics=dict(injected=0,read_frames=0,write_seconds=0,write_max_ms=0,write_batches=0)
        self.job=ProcessJob();self.output=(ROOT/'.runtime'/('stack-'+label+'.log')).open('w')
        env=os.environ.copy();env.pop('GAMEBOND_CAPTURE_TOKEN',None);env.pop('GAMEBOND_APP_AUTHORIZATION',None)
        self.child=subprocess.Popen([str(ROOT/'build/gamebond-netstack-attribution.exe'),'--proxy-stdio'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.output,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
        self.job.add(self.child)
        def read():
            while not self.stop.is_set():
                kind,size=struct.unpack('!BH',exact(self.child.stdout,3));packet=exact(self.child.stdout,size)
                if kind==2:
                    record=json.loads(packet)
                    if record.get('socks'):self.ready.put(record['socks'])
                elif kind==0:
                    self.metrics['read_frames']+=1
                    self.node.send(packet,False,parse_packet(packet).flow)
        def write():
            while not self.stop.is_set():
                try:packet=self.node.recv(.1)
                except queue.Empty:continue
                packets=[packet]
                for _ in range(self.batch-1):
                    try:packets.append(self.node.recv(0))
                    except queue.Empty:break
                started=time.perf_counter()
                data=b''.join(struct.pack('!BH',0,len(packet))+packet for packet in packets)
                self.child.stdin.write(data);self.child.stdin.flush()
                elapsed=time.perf_counter()-started
                self.metrics['injected']+=len(packets);self.metrics['write_batches']+=1
                self.metrics['write_seconds']+=elapsed;self.metrics['write_max_ms']=max(self.metrics['write_max_ms'],elapsed*1000)
        def guarded(fn):
            try:fn()
            except (OSError,EOFError,ValueError) as exc:
                if not self.stop.is_set():self.errors.append(str(exc));self.stop.set()
        for fn in (read,write):
            worker=threading.Thread(target=guarded,args=(fn,),daemon=True);worker.start();self.workers.append(worker)
        host,port=self.ready.get(timeout=4).rsplit(':',1);self.address=(host,int(port))

    def connect(self,target,port):
        stream=socket.create_connection(self.address,timeout=8);stream.settimeout(35)
        stream.sendall(b'\x05\x01\x00')
        if exact(stream,2)!=b'\x05\x00':raise RuntimeError('SOCKS negotiation failed')
        stream.sendall(b'\x05\x01\0\x01'+socket.inet_aton(target)+struct.pack('!H',port))
        if exact(stream,10)[:4]!=b'\x05\0\0\x01':raise RuntimeError('SOCKS connect failed')
        return stream

    def close(self):
        self.stop.set()
        if self.child.poll() is None:self.child.terminate()
        try:self.child.wait(timeout=3)
        finally:self.job.close()
        for worker in self.workers:worker.join(1)
        for pipe in (self.child.stdin,self.child.stdout):
            try:pipe.close()
            except OSError:pass
        self.output.close()
