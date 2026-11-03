"""Authenticate each physical link and check tunnel ICMP plus internet DNS."""
import json
from pathlib import Path
import queue
import secrets
import socket
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from probe_endpoint import ipv4,checksum

def check(config,key,indices):
    options=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,
                 probe_interval=.1,path_timeout=2,interface_indices=[config['interface_indices'][i] for i in indices])
    with Node(key,'client',bytes.fromhex(config['session']),[tuple(config['bind'][i]) for i in indices],tuple(config['peer']),**options) as node:
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            if all(p['healthy'] for p in node.stats()['paths']):break
            time.sleep(.05)
        else:raise RuntimeError(f'Path authentication failed: {indices}')
        ident=secrets.randbelow(65536)
        echo=struct.pack('!BBHHH',8,0,0,ident,1)+b'G'*1252
        echo=echo[:2]+struct.pack('!H',checksum(echo))+echo[4:]
        query_id=secrets.randbelow(65536)
        query=struct.pack('!HHHHHH',query_id,0x100,1,0,0,0)+b'\x07example\x03com\0\0\x01\0\x01'
        udp=struct.pack('!HHHH',49177,53,len(query)+8,0)+query
        started=time.monotonic()
        node.send(ipv4('10.77.0.1',1,echo))
        node.send(ipv4('1.1.1.1',17,udp))
        received={}
        while time.monotonic()-started<8 and len(received)<2:
            try:packet=node.recv(.25)
            except queue.Empty:continue
            offset=(packet[0]&15)*4
            if packet[9]==1 and len(packet)>=offset+8 and packet[offset]==0 and struct.unpack_from('!H',packet,offset+4)[0]==ident:
                received['icmp_full_mtu']=dict(bytes=len(packet),rtt_ms=(time.monotonic()-started)*1000)
            if packet[9]==17 and len(packet)>=offset+20:
                sport,dport=struct.unpack_from('!HH',packet,offset)
                if sport==53 and dport==49177 and struct.unpack_from('!H',packet,offset+8)[0]==query_id:
                    received['internet_dns']=dict(bytes=len(packet),rcode=packet[offset+11]&15)
        if len(received)!=2 or received['icmp_full_mtu']['bytes']!=1280 or received['internet_dns']['rcode']!=0:
            raise RuntimeError(f'Tunnel/NAT check failed on {indices}: {received}')
        return dict(indices=indices,results=received,paths=[{k:p[k] for k in ('local','remote','healthy','rtt_ms')} for p in node.stats()['paths']])

def main():
    config=json.loads((ROOT/'.runtime/edge195/client.json').read_text())
    key=(ROOT/'secrets/edge195.key').read_bytes()
    cases=[]
    for indices in ([0],[1],[0,1]):
        result=check(config,key,indices);cases.append(result)
        print(json.dumps(result),flush=True)
    (ROOT/'evidence/edge195-connectivity.json').write_text(json.dumps(dict(passed=True,peer=config['peer'],cases=cases),indent=2)+'\n')

if __name__=='__main__':main()
