"""Probe real HTTP/3 through a diagnostic tunnel's authenticated UDP relay.

Requires aioquic installed in .runtime/quic-libs. Never starts a second tunnel.
"""
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.runtime/quic-libs'))
sys.path.insert(0, str(ROOT))
import psutil
from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import HeadersReceived, DataReceived
from gamebond.userspace import read_exact, live_status


def probe(host='www.cloudflare.com', datagram_size=1350):
    status = live_status()
    if not status or status['state'] != 'running':
        raise RuntimeError('Start a diagnostic tunnel first')
    config = json.loads((ROOT/'.runtime/userspace-proxy/app-config.json').read_text())['proxies'][0]
    address, port = config['socks5ProxyEndpoint'].rsplit(':', 1)
    birth = round(psutil.Process().create_time()*10_000_000) + 116444736000000000
    username = f'gamebond-owner-v1|{os.getpid()}|{birth}'.encode()
    password = config['password'].encode()
    target = (socket.gethostbyname(host), 443)
    prefix = b'\0\0\0\1' + socket.inet_aton(target[0]) + struct.pack('!H',443)
    with socket.create_connection((address,int(port)),timeout=5) as control, control.makefile('rb') as reader, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        control.sendall(b'\5\1\2')
        assert read_exact(reader,2)==b'\5\2'
        control.sendall(b'\1'+bytes([len(username)])+username+bytes([len(password)])+password)
        assert read_exact(reader,2)==b'\1\0'
        control.sendall(b'\5\3\0\1'+b'\0'*6)
        reply=read_exact(reader,10)
        assert reply[:4]==b'\5\0\0\1'
        udp.connect((socket.inet_ntoa(reply[4:8]),struct.unpack('!H',reply[8:])[0]))
        udp.settimeout(.05)
        quic=QuicConnection(configuration=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,server_name=host,max_datagram_size=datagram_size))
        http=H3Connection(quic)
        quic.connect(target,now=time.time())
        stream=quic.get_next_available_stream_id()
        http.send_headers(stream,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',host.encode()),(b':path',b'/cdn-cgi/trace')],end_stream=True)
        body=bytearray(); headers=[]; started=time.time()
        while time.time()-started<20:
            now=time.time()
            timer=quic.get_timer()
            if timer is not None and timer<=now:quic.handle_timer(now=now)
            for data,_ in quic.datagrams_to_send(now=now):udp.send(prefix+data)
            try:
                data=udp.recv(65535)
                if data[:10]!=prefix:raise RuntimeError('Unexpected SOCKS reply source')
                quic.receive_datagram(data[10:],target,now=time.time())
            except socket.timeout:pass
            while (event:=quic.next_event()) is not None:
                if isinstance(event,ConnectionTerminated):raise RuntimeError(str(event))
                for item in http.handle_event(event):
                    if isinstance(item,HeadersReceived):headers.extend(item.headers)
                    if isinstance(item,DataReceived):body.extend(item.data)
                    if getattr(item,'stream_ended',False):
                        code=dict(headers).get(b':status',b'').decode()
                        trace=body.decode()
                        if code!='200' or f"ip={status['peer'][0]}" not in trace:
                            raise RuntimeError(f'Invalid HTTP/3 response: {code} {trace}')
                        return dict(passed=True,protocol='h3',host=host,datagram_size=datagram_size,bytes=len(body),seconds=round(time.time()-started,3),egress_ipv4=status['peer'][0])
        raise TimeoutError('HTTP/3 proxy probe timed out')


if __name__=='__main__':
    print(json.dumps(probe()))
