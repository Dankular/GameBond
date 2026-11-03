"""Raw IP UDP diagnostic to isolate multipath transport from inner TCP."""
import json
from pathlib import Path
import queue
import secrets
import socket
import struct
import sys
import time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from gamebond.userspace import available_link_config
from gamebond.windows_adapters import discover_adapters
from probe_endpoint import ipv4

def main():
    candidate=json.loads((ROOT/'.runtime/outer-stage/candidate.json').read_text());original=json.loads((ROOT/'configs/local-client.json').read_text())
    config,_=available_link_config(original,discover_adapters());results=[]
    try:
        for case in ('0','1','01'):
            slots=list(map(int,case));identifier=secrets.token_hex(6);seconds=10
            node=Node((ROOT/original['key_file']).read_bytes(),'client',bytes.fromhex(candidate['session']),
                [tuple(config['bind'][i]) for i in slots],tuple(candidate['peer']),interface_indices=[config['interface_indices'][i] for i in slots],
                bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD).start()
            try:
                deadline=time.monotonic()+8
                while not all(p['healthy'] for p in node.stats()['paths']):
                    if time.monotonic()>deadline:raise RuntimeError('Handshake timeout')
                    time.sleep(.05)
                data=json.dumps(dict(type='GBUDP1',id=identifier,seconds=seconds,rate_mbps=100)).encode()
                udp=struct.pack('!HHHH',49179,8081,len(data)+8,0)+data
                node.send(ipv4('10.77.0.1',17,udp,dscp=0),True)
                count=0;seen=set();start=None;bins=[0]*20;deadline=time.monotonic()+18
                while time.monotonic()<deadline:
                    try:packet=node.recv(.1)
                    except queue.Empty:
                        if start and time.monotonic()-start>seconds+1:break
                        continue
                    offset=(packet[0]&15)*4+8;body=packet[offset:]
                    if len(body)!=1200 or body[:10]!=b'GBUP'+bytes.fromhex(identifier):continue
                    if body[18:]!=b'Q'*1182:raise RuntimeError('UDP integrity failed')
                    if start is None:start=time.monotonic()
                    sequence=struct.unpack_from('!Q',body,10)[0]
                    if sequence not in seen:
                        seen.add(sequence);count+=1;bins[min(19,int(time.monotonic()-start))]+=len(body)
                if not start:raise RuntimeError('No UDP benchmark traffic received')
                row=dict(case=case,received_datagrams=count,steady_datagram_mbps=sum(bins[3:seconds])*8/(seconds-3)/1e6,
                         one_second_bytes=bins,client=node.stats())
                results.append(row);print(json.dumps({k:row[k] for k in ('case','received_datagrams','steady_datagram_mbps')}),flush=True)
            finally:node.close()
    finally:(ROOT/'evidence/physical-udp-transport-diagnostic.json').write_text(json.dumps(dict(scope='Single UDP virtual flow, diagnostic only; not TCP aggregation proof',results=results),indent=2)+'\n')

if __name__=='__main__':main()
