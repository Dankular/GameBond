"""Verify negotiated link policies against an isolated VPS TUN endpoint."""
import json
from pathlib import Path
import queue
import secrets
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from gamebond.link_policy import LinkPolicy,operational_state
from netstack_wan import WanEndpoint
from probe_endpoint import ipv4,checksum


def state(role,rate=0):
    return operational_state(LinkPolicy(role=role,upload_mbps=rate,download_mbps=rate),dict(daily_bytes=0,monthly_bytes=0))


def wait(predicate,seconds=10):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.05)
    raise RuntimeError('VPS did not acknowledge link policy')


def echo(node,count):
    ident=secrets.randbelow(65536);started=time.perf_counter()
    before=node.stats()
    for sequence in range(count):
        payload=struct.pack('!BBHHH',8,0,0,ident,sequence)+b'P'*1252
        payload=payload[:2]+struct.pack('!H',checksum(payload))+payload[4:]
        if node.send(ipv4('10.77.0.1',1,payload,dscp=0),False,('icmp',ident))!=1:raise RuntimeError('Policy prevented usable-link send')
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            try:packet=node.recv(.1)
            except queue.Empty:continue
            offset=(packet[0]&15)*4
            if packet[9]==1 and packet[offset]==0 and struct.unpack_from('!HH',packet,offset+4)==(ident,sequence):break
        else:raise RuntimeError('Policy round trip failed')
    return dict(packets=count,seconds=time.perf_counter()-started,before=before,after=node.stats())


def main():
    config=json.loads((ROOT/'configs/local-client.json').read_text());key=secrets.token_bytes(32);session=secrets.token_bytes(16)
    reports=[]
    with WanEndpoint(key,session) as endpoint:
        with Node(key,'client',session,[tuple(b) for b in config['bind']],(endpoint.host,endpoint.port),
                  interface_indices=config['interface_indices'],bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,
                  probe_interval=.1,path_timeout=2,link_states=[state('primary'),state('backup')]) as node:
            wait(lambda:all(p['healthy'] for p in node.stats()['paths']))
            reports.append(dict(case='primary-with-standby-backup',result=echo(node,12)))
            time.sleep(1.1)
            reports[-1]['server']=json.loads(endpoint.command(['docker','exec',endpoint.name,'cat','/tmp/result.json']))['transport']
            primary=next(p for p in reports[-1]['server']['paths'] if p['link_policy']['role']=='primary')
            backup=next(p for p in reports[-1]['server']['paths'] if p['link_policy']['role']=='backup')
            if not primary['bonding']['sent_packets'] or backup['bonding']['sent_packets']:
                raise RuntimeError('VPS did not reserve the backup link')
            node.set_link_states([state('never'),state('primary',.25)])
            wait(lambda:all(p['policy_confirmed'] for p in node.stats()['paths']))
            reports.append(dict(case='first-disabled-second-rate-limited',result=echo(node,30)))
            result=reports[-1]['result'];before=result['before']['paths'][1];after=result['after']['paths'][1]
            for field in ('wire_tx_bytes','metered_download_bytes'):
                if after[field]-before[field]>.25*125000*result['seconds']+5600:
                    raise RuntimeError('Physical configured rate limit was exceeded')
            if result['after']['paths'][0]['bonding']['sent_packets']!=result['before']['paths'][0]['bonding']['sent_packets']:
                raise RuntimeError('Disabled path carried bulk data')
    report=dict(passed=True,peer=config['peer'],scope='Both physical links, isolated VPS container, full-MTU ICMP over encrypted tunnel',cases=reports)
    (ROOT/'evidence/link-policies-wan.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=[r['case'] for r in reports])))


if __name__=='__main__':main()
