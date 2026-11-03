"""Bounded authenticated datagram carriage over TCP, TLS or HTTPS CONNECT.

This transports already encrypted GameBond packets to one fixed UDP endpoint.
It is not a general-purpose proxy. TLS/HTTPS require normal CA and hostname
verification; every mode also proves possession of the configured session PSK.
"""
from collections import Counter
from dataclasses import dataclass
import hmac
import queue
import select
import secrets
import socket
import ssl
import struct
import threading
import time

MAGIC=b'GBCAR01\n'
AUTHORITY=b'gamebond.invalid:443'
MAX_FRAME=2048
MAX_HEADER=4096

@dataclass(frozen=True)
class RelaySettings:
    bind:tuple
    mode:str='tls'
    cert_file:str|None=None
    key_file:str|None=None
    max_clients:int=16

    def __post_init__(self):
        if self.mode not in ('tcp','tls','https'):raise ValueError('Invalid relay mode')
        if not isinstance(self.bind,(list,tuple)) or len(self.bind)!=2:raise ValueError('Invalid relay bind')
        socket.inet_aton(self.bind[0])
        if type(self.bind[1]) is not int or not 1<=self.bind[1]<=65535:raise ValueError('Invalid relay port')
        if self.mode!='tcp' and (not isinstance(self.cert_file,str) or not isinstance(self.key_file,str) or not self.cert_file or not self.key_file):
            raise ValueError('TLS relay requires server certificate and private key files')
        if type(self.max_clients) is not int or not 1<=self.max_clients<=32:raise ValueError('Invalid relay client bound')

    def context(self):
        if self.mode=='tcp':return None
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert_file,self.key_file)
        return context

def read_exact(stream,size,deadline=None,stop=None):
    result=bytearray()
    while len(result)<size:
        if stop is not None and stop.is_set():raise EOFError('Carrier stopped')
        if deadline is not None and time.monotonic()>deadline:raise TimeoutError('Carrier read deadline exceeded')
        try:part=stream.recv(size-len(result))
        except socket.timeout:continue
        if not part:raise EOFError('Carrier peer closed')
        result.extend(part)
    return bytes(result)

def read_header(stream,deadline=None):
    result=bytearray();deadline=deadline or time.monotonic()+3
    while not result.endswith(b'\r\n\r\n'):
        if len(result)>=MAX_HEADER:raise ValueError('HTTPS CONNECT header too large')
        result.extend(read_exact(stream,1,deadline))
    return bytes(result)

def authenticate(stream,key,session,mode,*,server=False,deadline=None):
    if len(key)!=32 or len(session)!=16:raise ValueError('Invalid carrier key or session')
    label=b'gamebond-carrier-v1/'+mode.encode('ascii')
    deadline=deadline or time.monotonic()+3
    if server:
        nonce=secrets.token_bytes(32);stream.sendall(MAGIC+nonce)
        response=read_exact(stream,80,deadline)
        identity,client_nonce,proof=response[:16],response[16:48],response[48:]
        transcript=label+nonce+identity+client_nonce
        expected=hmac.digest(key,b'client/'+transcript,'sha256')
        if not hmac.compare_digest(identity,session) or not hmac.compare_digest(proof,expected):raise ValueError('Carrier authentication rejected')
        stream.sendall(hmac.digest(key,b'server/'+transcript,'sha256'))
    else:
        challenge=read_exact(stream,40,deadline)
        if challenge[:8]!=MAGIC:raise ValueError('Invalid carrier greeting')
        nonce=secrets.token_bytes(32);transcript=label+challenge[8:]+session+nonce
        stream.sendall(session+nonce+hmac.digest(key,b'client/'+transcript,'sha256'))
        proof=read_exact(stream,32,deadline)
        if not hmac.compare_digest(proof,hmac.digest(key,b'server/'+transcript,'sha256')):raise ValueError('Carrier server authentication rejected')

def open_client(endpoint,key,session,mode,*,source=None,interface_index=None,ca_file=None,server_name=None,timeout=3,on_socket=None):
    if mode not in ('tcp','tls','https'):raise ValueError('Unknown outer transport')
    socket.inet_pton(socket.AF_INET,endpoint[0])
    deadline=time.monotonic()+timeout
    raw=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        if on_socket:on_socket(raw)
        raw.settimeout(timeout);raw.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        raw.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16384)
        if interface_index is not None:
            raw.setsockopt(socket.IPPROTO_IP,getattr(socket,'IP_UNICAST_IF',31),struct.pack('=I',socket.htonl(interface_index)))
        if source:raw.bind((source,0))
        raw.connect(tuple(endpoint))
        if mode!='tcp':
            if not ca_file:raise ValueError('TLS carrier requires a trusted CA file')
            context=ssl.create_default_context(cafile=str(ca_file));context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(['http/1.1' if mode=='https' else 'gamebond/1'])
            raw.settimeout(max(.001,deadline-time.monotonic()))
            raw=context.wrap_socket(raw,server_hostname=server_name or endpoint[0])
            if on_socket:on_socket(raw)
        raw.settimeout(.5)
        if mode=='https':
            raw.sendall(b'CONNECT '+AUTHORITY+b' HTTP/1.1\r\nHost: '+AUTHORITY+b'\r\n\r\n')
            if read_header(raw,deadline).split(b'\r\n',1)[0]!=b'HTTP/1.1 200 Connection Established':raise ValueError('HTTPS CONNECT rejected')
        authenticate(raw,key,session,mode,deadline=deadline)
        return raw
    except BaseException:
        raw.close();raise

def send_frame(stream,packet):
    if not 1<=len(packet)<=MAX_FRAME:raise ValueError('Carrier datagram exceeds its bound')
    stream.sendall(struct.pack('!H',len(packet))+packet)

def receive_frame(stream,stop=None):
    deadline=time.monotonic()+30
    size=struct.unpack('!H',read_exact(stream,2,deadline,stop))[0]
    if not 1<=size<=MAX_FRAME:raise ValueError('Invalid carrier datagram length')
    return read_exact(stream,size,deadline,stop)

def pump_stream(stream,outgoing,on_packet,stopped,*,upstream=None,count=lambda name,size:None):
    """One owner for SSL reads/writes; bounded partial-frame buffers and queues."""
    stream.setblocking(False)
    if upstream:upstream.setblocking(False)
    received=bytearray();sending=b'';order=0;last_read=time.monotonic()
    while not stopped():
        if time.monotonic()-last_read>30:raise TimeoutError('Carrier idle timeout')
        if not sending:
            try:packet=outgoing.get_nowait()[-1];sending=struct.pack('!H',len(packet))+packet
            except queue.Empty:pass
        pending=isinstance(stream,ssl.SSLSocket) and stream.pending()>0
        readable,writable,_=select.select([stream]+([upstream] if upstream else []),[stream] if sending else [],[],0 if pending else .01)
        if pending or stream in readable:
            try:part=stream.recv(4096)
            except (ssl.SSLWantReadError,ssl.SSLWantWriteError,BlockingIOError):part=None
            if part==b'':raise EOFError('Carrier peer closed')
            if part:
                last_read=time.monotonic();received.extend(part);count('rx_framed_bytes',len(part))
                if len(received)>MAX_FRAME*4:raise ValueError('Carrier receive buffer overflow')
                while len(received)>=2:
                    size=struct.unpack_from('!H',received)[0]
                    if not 1<=size<=MAX_FRAME:raise ValueError('Invalid carrier datagram length')
                    if len(received)<size+2:break
                    packet=bytes(received[2:size+2]);del received[:size+2];on_packet(packet)
        if upstream and upstream in readable:
            try:packet=upstream.recv(MAX_FRAME+1)
            except BlockingIOError:packet=None
            if packet:
                if len(packet)>MAX_FRAME:raise ValueError('Carrier datagram exceeds its bound')
                order+=1
                try:outgoing.put_nowait((0 if len(packet)>36 and packet[36]!=4 else 1,order,packet))
                except queue.Full:count('send_queue_drops',1)
        if sending and stream in writable:
            try:written=stream.send(sending)
            except (ssl.SSLWantReadError,ssl.SSLWantWriteError,BlockingIOError):written=0
            if written:count('tx_framed_bytes',written);sending=sending[written:]

class CarrierRelay:
    """Fixed-destination relay; authenticate before allocating any UDP socket."""
    def __init__(self,bind,udp_peer,key,session,*,mode='tls',context=None,max_clients=16):
        if mode not in ('tcp','tls','https') or mode!='tcp' and context is None:raise ValueError('Invalid relay transport')
        if not 1<=max_clients<=32:raise ValueError('Carrier client limit must be 1..32')
        self.key,self.session=key,session;self.mode=mode;self.context=context;self.udp_peer=tuple(udp_peer)
        self.stop=threading.Event();self.lock=threading.Lock();self.connections=set();self.workers=set()
        self.slots=threading.BoundedSemaphore(max_clients);self.counts=Counter()
        self.last_error=None
        self.listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.listener.bind(tuple(bind));self.listener.listen(max_clients);self.listener.settimeout(.2)
        if context:context.set_alpn_protocols(['gamebond/1','http/1.1'])
        self.thread=threading.Thread(target=self._accept,daemon=True,name='gamebond-carrier-listener')

    @property
    def address(self):return self.listener.getsockname()
    def start(self):self.thread.start();return self

    def _accept(self):
        while not self.stop.is_set():
            try:connection,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            if not self.slots.acquire(False):connection.close();continue
            with self.lock:self.connections.add(connection)
            worker=threading.Thread(target=self._serve,args=(connection,),daemon=True,name='gamebond-carrier-relay')
            with self.lock:self.workers.add(worker)
            worker.start()

    def _serve(self,connection):
        original=connection;upstream=None
        try:
            connection.settimeout(3);connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            connection.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16384)
            mode=self.mode
            if self.context:
                connection=self.context.wrap_socket(connection,server_side=True)
                with self.lock:self.connections.discard(original);self.connections.add(connection)
                mode='https' if connection.selected_alpn_protocol()=='http/1.1' else 'tls'
            connection.settimeout(.5)
            if mode=='https':
                header=read_header(connection)
                lines=header.split(b'\r\n')
                if lines[0]!=b'CONNECT '+AUTHORITY+b' HTTP/1.1' or any(line.lower().startswith((b'content-length:',b'transfer-encoding:')) for line in lines[1:]):
                    raise ValueError('Only the fixed GameBond CONNECT destination is accepted')
                connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            authenticate(connection,self.key,self.session,mode,server=True)
            with self.lock:self.counts['authenticated']+=1
            upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.connect(self.udp_peer);upstream.settimeout(.2)
            def consume(packet):
                try:upstream.send(packet)
                except BlockingIOError:
                    with self.lock:self.counts['up_datagram_drops']+=1
                    return
                with self.lock:self.counts['up_datagrams']+=1
            def count(name,size):
                mapped={'rx_framed_bytes':'up_framed_bytes','tx_framed_bytes':'down_framed_bytes'}.get(name,name)
                with self.lock:self.counts[mapped]+=size
            pump_stream(connection,queue.PriorityQueue(maxsize=32),consume,self.stop.is_set,upstream=upstream,count=count)
        except (OSError,EOFError,ValueError) as exc:
            with self.lock:self.counts['rejected_or_closed']+=1;self.last_error=str(exc)[:256]
        finally:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            connection.close()
            if upstream:upstream.close()
            with self.lock:
                self.connections.discard(connection);self.connections.discard(original)
                self.workers.discard(threading.current_thread())
            self.slots.release()

    def stats(self):
        with self.lock:return {**self.counts,'active_connections':len(self.connections),'last_error':self.last_error}

    def close(self):
        self.stop.set();self.listener.close()
        with self.lock:connections=list(self.connections);workers=list(self.workers)
        for connection in connections:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            connection.close()
        if self.thread.is_alive():self.thread.join(1)
        for worker in workers:worker.join(2)
