"""Bounded diagnostic UDP source, private TUN address only."""
import json
import socket
import struct
import threading
import time
from pathlib import Path

stop=threading.Event();active=threading.Lock()

def send(udp,peer,request):
    try:
        seconds=float(request['seconds']);rate=float(request.get('rate_mbps',100));identifier=bytes.fromhex(request['id'])
        if not 1<=seconds<=30 or not 1<=rate<=200 or len(identifier)!=6:return
        payload=b'GBUP'+identifier;sequence=0;start=time.monotonic();interval=32*1200*8/(rate*1e6);next_send=start
        while time.monotonic()-start<seconds and not stop.is_set():
            for _ in range(32):
                try:udp.sendto(payload+struct.pack('!Q',sequence)+b'Q'*1182,peer)
                except OSError:pass
                sequence+=1
            next_send+=interval;stop.wait(max(0,next_send-time.monotonic()))
        Path('/tmp/udp-throughput-result.json').write_text(json.dumps(dict(id=request['id'],datagrams_attempted=sequence,seconds=time.monotonic()-start)))
    finally:active.release()

def main():
    deadline=time.monotonic()+1200
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.bind(('10.77.0.1',8081));udp.settimeout(.2)
        while time.monotonic()<deadline:
            try:data,peer=udp.recvfrom(512)
            except socket.timeout:continue
            if peer[0]!='10.77.0.2':continue
            try:request=json.loads(data)
            except ValueError:continue
            if request.get('type')=='GBUDP1' and active.acquire(False):threading.Thread(target=send,args=(udp,peer,request),daemon=True).start()
    stop.set()

if __name__=='__main__':main()
