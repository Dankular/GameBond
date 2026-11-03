"""Selectable per-link UDP/stream socket with bounded queues and explicit metrics."""
from collections import Counter,deque
from dataclasses import dataclass
import math
from pathlib import Path
import queue
import select
import socket
import threading
import time

from .stream_carrier import open_client,pump_stream,MAX_FRAME

@dataclass(frozen=True)
class StreamEndpoint:
    mode:str
    port:int
    ca_file:str|None=None
    server_name:str|None=None

    def __post_init__(self):
        if self.mode not in ('tcp','tls','https') or type(self.port) is not int or not 1<=self.port<=65535:raise ValueError('Invalid stream endpoint')
        if self.mode!='tcp' and (not isinstance(self.ca_file,str) or not self.ca_file):raise ValueError('TLS/HTTPS need a trusted CA file')
        if self.server_name is not None and (not isinstance(self.server_name,str) or len(self.server_name)>253 or '\0' in self.server_name):raise ValueError('Invalid TLS server name')

@dataclass(frozen=True)
class OuterSettings:
    endpoints:tuple=()
    fallback_after:float=1.5
    recovery_interval:float=5
    queue_packets:int=32

    def __post_init__(self):
        if not isinstance(self.endpoints,(list,tuple)) or not 1<=len(self.endpoints)<=3:raise ValueError('Configure one to three fallback endpoints')
        parsed=tuple(e if isinstance(e,StreamEndpoint) else StreamEndpoint(**e) for e in self.endpoints)
        if len({(e.mode,e.port) for e in parsed})!=len(parsed):raise ValueError('Duplicate fallback endpoint')
        object.__setattr__(self,'endpoints',parsed)
        for name in ('fallback_after','recovery_interval'):
            value=getattr(self,name)
            if type(value) not in (float,int) or not math.isfinite(value) or not .1<=value<=300:raise ValueError('Invalid carrier timer')
        if type(self.queue_packets) is not int or not 1<=self.queue_packets<=128:raise ValueError('Invalid carrier queue bound')

class CarrierSocket:
    """A UDP-like socket; only authenticated Node callbacks establish link health."""
    def __init__(self,raw,peer,key,session,settings,interface_index=None):
        self.raw,self.peer,self.key,self.session=raw,tuple(peer),key,session;self.settings=settings
        self.interface_index=interface_index;self.source=raw.getsockname()[0]
        self.lock=threading.RLock();self.stop=threading.Event();self.activate=threading.Event()
        self.mode='udp';self.ready=False;self.connection=None;self.last_error=None
        self.created=time.perf_counter();self.last_udp_auth=self.created;self.last_recovery=0
        self.last_received_transport=None;self.counts=Counter();self.received=deque();self.notified=False
        self.connection_generation=0;self.last_received_generation=0;self.confirmed_generation=-1
        self.outgoing=queue.PriorityQueue(maxsize=settings.queue_packets);self.order=0
        self.wake=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.wake.bind(('127.0.0.1',0));self.wake.setblocking(False)
        self.signal=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.signal.connect(self.wake.getsockname());self.signal.setblocking(False)
        self.raw.setblocking(False)
        self.workers=[threading.Thread(target=fn,daemon=True,name=name) for fn,name in
                      ((self._udp_read,'gamebond-outer-udp'),(self._stream_loop,'gamebond-outer-stream'))]
        for worker in self.workers:worker.start()

    def fileno(self):return self.wake.fileno()
    def getsockname(self):return self.raw.getsockname()
    def getsockopt(self,*args):return self.raw.getsockopt(*args)

    def _enqueue_received(self,packet,endpoint,transport,generation=0):
        with self.lock:
            if self.stop.is_set():return
            if len(self.received)>=256:self.counts['receive_queue_drops']+=1;return
            self.received.append((packet,endpoint,transport,generation))
            if not self.notified:
                try:self.signal.send(b'1');self.notified=True
                except OSError:self.received.pop()

    def recvfrom(self,size):
        self.wake.recv(1)
        with self.lock:
            if not self.received:self.notified=False;raise BlockingIOError()
            packet,endpoint,self.last_received_transport,self.last_received_generation=self.received.popleft()
            self.notified=False
            if self.received:
                try:self.signal.send(b'1');self.notified=True
                except OSError:pass
        return packet[:size],endpoint

    def sendto(self,packet,endpoint):
        if tuple(endpoint)!=self.peer:raise ValueError('Carrier accepts only the configured peer')
        with self.lock:
            mode=self.mode
            if mode=='udp':return self.raw.sendto(packet,self.peer)
            if not self.ready:raise BlockingIOError('Fallback is reconnecting')
            if not 1<=len(packet)<=MAX_FRAME:raise ValueError('Carrier frame too large')
            urgent=len(packet)>36 and packet[36]!=4
            self.order+=1
            try:self.outgoing.put_nowait((0 if urgent else 1,self.order,bytes(packet)))
            except queue.Full:self.counts['send_queue_drops']+=1;raise BlockingIOError('Carrier queue full')
            return len(packet)

    def send_udp_probe(self,packet):return self.raw.sendto(packet,self.peer)

    def note_authenticated(self):
        with self.lock:
            if self.last_received_transport=='udp':self.last_udp_auth=time.perf_counter()
            elif self.last_received_generation==self.connection_generation:self.confirmed_generation=self.connection_generation

    def tick(self,now):
        with self.lock:
            if now-self.last_udp_auth>=self.settings.fallback_after:self.activate.set()

    def return_to_udp(self):
        with self.lock:
            self.last_udp_auth=time.perf_counter();self.mode='udp';self.ready=False;self.activate.clear()
            self.counts['udp_recoveries']+=1;connection=self.connection
            self._drain_outgoing()
        if connection:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass

    def _drain_outgoing(self):
        while True:
            try:self.outgoing.get_nowait();self.counts['discarded_on_transition']+=1
            except queue.Empty:break

    def _udp_read(self):
        while not self.stop.is_set():
            try:
                if not select.select([self.raw],[],[],.1)[0]:continue
                packet,endpoint=self.raw.recvfrom(MAX_FRAME+1)
                if tuple(endpoint)!=self.peer:continue
                self._enqueue_received(packet,endpoint,'udp')
            except BlockingIOError:continue
            except (OSError,ValueError):break

    def _track_socket(self,connection):
        with self.lock:
            if self.stop.is_set() or not self.activate.is_set():connection.close();raise EOFError('Fallback cancelled')
            self.connection=connection

    def _stream_loop(self):
        backoff=.25
        while not self.stop.is_set():
            if not self.activate.wait(.1):continue
            connected=False
            for endpoint in self.settings.endpoints:
                if self.stop.is_set() or not self.activate.is_set():break
                connection=None
                try:
                    with self.lock:self.counts['connection_attempts']+=1
                    connection=open_client((self.peer[0],endpoint.port),self.key,self.session,endpoint.mode,
                        source=self.source,interface_index=self.interface_index,ca_file=endpoint.ca_file,
                        server_name=endpoint.server_name,on_socket=self._track_socket)
                    with self.lock:
                        if self.stop.is_set() or not self.activate.is_set():raise EOFError('Fallback cancelled')
                        self.connection=connection;self.mode=endpoint.mode;self.ready=True;self.last_error=None
                        self.counts['connections']+=1
                        self.connection_generation+=1;generation=self.connection_generation
                    connected=True;backoff=.25
                    def consume(packet):self._enqueue_received(packet,self.peer,endpoint.mode,generation)
                    def count(name,size):
                        with self.lock:self.counts[name]+=size
                    pump_stream(connection,self.outgoing,consume,lambda:self.stop.is_set() or not self.activate.is_set(),count=count)
                except (OSError,EOFError,ValueError) as exc:
                    with self.lock:self.last_error=str(exc)[:256];self.counts['connection_errors']+=1
                finally:
                    if connection:
                        try:connection.shutdown(socket.SHUT_RDWR)
                        except OSError:pass
                        connection.close()
                    with self.lock:self.ready=False;self.connection=None;self._drain_outgoing()
                if connected:break
            self.stop.wait(backoff);backoff=min(5,backoff*2)

    def stats(self):
        with self.lock:return dict(mode=self.mode,ready=self.ready,last_error=self.last_error,
            peer_confirmed=self.ready and self.confirmed_generation==self.connection_generation,
            queue_packets=self.outgoing.qsize(),queue_limit=self.settings.queue_packets,counters=dict(self.counts),
            accounting_scope='Framed encrypted GameBond datagrams; excludes TLS/TCP/IP overhead and TCP retransmissions')

    def close(self):
        self.stop.set();self.activate.set()
        with self.lock:connection=self.connection
        if connection:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            connection.close()
        self.raw.close();self.wake.close();self.signal.close()
