"""TLS kernel-TCP baseline bound to each physical adapter, no tunnel path."""
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import sys
import time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from gamebond.userspace import available_link_config
from gamebond.windows_adapters import discover_adapters

def main():
    directory=ROOT/'.runtime/direct-benchmark';target=json.loads((directory/'candidate.json').read_text())
    config,_=available_link_config(json.loads((ROOT/'configs/local-client.json').read_text()),discover_adapters())
    rows=[]
    try:
        for slot in range(2):
            raw=socket.socket(socket.AF_INET,socket.SOCK_STREAM);raw.settimeout(20)
            index=config['interface_indices'][slot]
            raw.setsockopt(socket.IPPROTO_IP,getattr(socket,'IP_UNICAST_IF',31),struct.pack('=I',socket.htonl(index)))
            raw.bind((config['bind'][slot][0],0));raw.connect((target['peer'],target['port']))
            context=ssl.create_default_context(cafile=target['ca_file']);context.minimum_version=ssl.TLSVersion.TLSv1_2
            with context.wrap_socket(raw,server_hostname=target['peer']) as stream:
                request=dict(id=secrets.token_hex(6),direction='download',seconds=12,token=(directory/'token').read_text().strip())
                stream.sendall(json.dumps(request).encode()+b'\n');ready=bytearray()
                while not ready.endswith(b'\n'):
                    part=stream.recv(1)
                    if not part:raise EOFError('Direct benchmark closed before readiness')
                    ready.extend(part)
                assert json.loads(ready)==dict(ready=True)
                start=time.perf_counter();total=0;bins=[0]*22
                while True:
                    chunk=stream.recv(65536);elapsed=time.perf_counter()-start
                    if not chunk:break
                    assert chunk.count(b'Z')==len(chunk);total+=len(chunk);bins[min(21,int(elapsed))]+=len(chunk)
            row=dict(id=request['id'],interface_index=index,seconds=elapsed,payload_bytes=total,payload_mbps=total*8/elapsed/1e6,
                     steady_payload_mbps=sum(bins[4:12])*8/8/1e6,duration_complete=elapsed>=11.4)
            rows.append(row);print(json.dumps(row),flush=True)
    finally:(ROOT/'evidence/direct-physical-kernel-tcp.json').write_text(json.dumps(dict(scope='Direct physical TLS kernel-TCP baseline; Python carrier excluded from capture',results=rows),indent=2)+'\n')

if __name__=='__main__':main()
