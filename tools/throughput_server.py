"""Bounded private-TUN benchmark service with Linux TCP_INFO observations."""
import json
import argparse
import hmac
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import threading
import time
from collections import deque

stop=threading.Event();lock=threading.Lock();results=deque(maxlen=128);slots=threading.BoundedSemaphore(8)
public=False;tls_context=None;token=None
signal.signal(signal.SIGTERM,lambda *_:stop.set());signal.signal(signal.SIGINT,lambda *_:stop.set())

def tcp_info(connection):
    raw=connection.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,256)
    offsets=dict(rto_us=8,snd_mss=16,unacked=24,lost=32,retrans=36,rtt_us=68,rttvar_us=72,snd_ssthresh=76,snd_cwnd=80,total_retrans=100)
    row={key:struct.unpack_from('=I',raw,offset)[0] for key,offset in offsets.items() if len(raw)>=offset+4}
    for name,offset in (('bytes_acked',120),('bytes_received',128),('pacing_rate',104),('delivery_rate',160),('rwnd_limited_us',176),('sndbuf_limited_us',184)):
        if len(raw)>=offset+8:row[name]=struct.unpack_from('=Q',raw,offset)[0]
    return row

def run(connection,peer):
    row={};started=None
    try:
        if tls_context:
            connection.settimeout(3);connection=tls_context.wrap_socket(connection,server_side=True)
        with connection:
            if not public and peer[0]!='10.77.0.2':return
            connection.settimeout(5);connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            request=bytearray()
            while not request.endswith(b'\n'):
                if len(request)>=512:raise ValueError('Request too long')
                part=connection.recv(1)
                if not part:raise EOFError()
                request.extend(part)
            request=json.loads(request);seconds=request['seconds'];limit=request.get('limit_bytes',256*1024*1024)
            if public and not hmac.compare_digest(str(request.get('token','')),token):raise ValueError('Benchmark authorization failed')
            if type(seconds) not in (int,float) or not 1<=seconds<=30 or type(limit) is not int or not 1024<=limit<=512*1024*1024:raise ValueError('Invalid benchmark bound')
            if request['direction'] not in ('download','upload'):raise ValueError('Invalid direction')
            row=dict(id=str(request['id'])[:64],direction=request['direction'],requested_seconds=seconds,samples=[],bytes=0)
            connection.sendall(b'{"ready":true}\n');started=time.monotonic();cpu=time.process_time();next_sample=started
            chunk=b'Z'*65536
            if request['direction']=='download':
                while time.monotonic()-started<seconds and row['bytes']<limit and not stop.is_set():
                    count=min(len(chunk),limit-row['bytes']);connection.sendall(chunk[:count]);row['bytes']+=count
                    if time.monotonic()>=next_sample:
                        row['samples'].append(dict(seconds=time.monotonic()-started,bytes=row['bytes'],**tcp_info(connection)))
                        next_sample=time.monotonic()+.5
            else:
                connection.settimeout(seconds+5)
                while row['bytes']<limit and time.monotonic()-started<seconds+5:
                    chunk=connection.recv(65536)
                    if not chunk:break
                    if chunk.count(b'U')!=len(chunk):raise ValueError('Upload integrity failed')
                    row['bytes']+=len(chunk)
                    if time.monotonic()>=next_sample:
                        row['samples'].append(dict(seconds=time.monotonic()-started,bytes=row['bytes'],**tcp_info(connection)))
                        next_sample=time.monotonic()+.5
                connection.sendall(json.dumps(dict(received_bytes=row['bytes'])).encode()+b'\n')
            row.update(seconds=time.monotonic()-started,cpu_seconds=time.process_time()-cpu,final_tcp=tcp_info(connection),limit_reached=row['bytes']>=limit)
    except (OSError,ValueError,EOFError,KeyError) as exc:row['error']=str(exc)
    finally:
        with lock:
            results.append(row);path=Path('/tmp/throughput-results.json');temporary=path.with_suffix('.tmp')
            temporary.write_text(json.dumps(list(results)));temporary.replace(path)
        slots.release()

def main():
    global public,tls_context,token
    parser=argparse.ArgumentParser();parser.add_argument('--public',action='store_true');parser.add_argument('--cert');parser.add_argument('--key');parser.add_argument('--token-file')
    args=parser.parse_args();public=args.public
    if public:
        if not all((args.cert,args.key,args.token_file)):raise ValueError('Public benchmark requires TLS and a token')
        token=Path(args.token_file).read_text().strip()
        if len(token)<32:raise ValueError('Benchmark token is too short')
        tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls_context.minimum_version=ssl.TLSVersion.TLSv1_2;tls_context.load_cert_chain(args.cert,args.key)
    deadline=time.monotonic()+1200
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('0.0.0.0' if public else '10.77.0.1',8080));listener.listen(8);listener.settimeout(.2)
        Path('/tmp/throughput-ready.json').write_text(json.dumps(dict(pid=os.getpid(),state='running')))
        while not stop.is_set() and time.monotonic()<deadline:
            try:connection,peer=listener.accept()
            except socket.timeout:continue
            if not slots.acquire(False):connection.close();continue
            threading.Thread(target=run,args=(connection,peer),daemon=True).start()
    stop.set();Path('/tmp/throughput-ready.json').write_text(json.dumps(dict(pid=os.getpid(),state='stopped')))

if __name__=='__main__':main()
