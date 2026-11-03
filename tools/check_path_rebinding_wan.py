"""Isolated socket loss/rebind against the configured VPS, no host NIC changes."""
import json
from pathlib import Path
import queue
import secrets
import struct
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from gamebond.userspace import live_status,available_link_config
from gamebond.windows_adapters import discover_adapters,AdapterNotifications
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from probe_endpoint import ipv4,checksum

def wait(predicate):
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.02)
    raise RuntimeError('VPS path did not authenticate')

def echo(node):
    identity=secrets.randbelow(65536)
    message=struct.pack('!BBHHH',8,0,0,identity,1)+b'address-lifecycle'
    message=message[:2]+struct.pack('!H',checksum(message))+message[4:]
    start=time.monotonic();node.send(ipv4('10.77.0.1',1,message),True)
    while time.monotonic()-start<5:
        try:packet=node.recv(.2)
        except queue.Empty:continue
        offset=(packet[0]&15)*4
        if packet[9]==1 and packet[offset]==0 and packet[offset+4:offset+6]==struct.pack('!H',identity):
            return round((time.monotonic()-start)*1000,3)
    raise RuntimeError('No authenticated VPS ICMP echo')

def main():
    if live_status():raise RuntimeError('Leave the active tunnel untouched')
    original=json.loads((ROOT/'configs/local-client.json').read_text())
    config,missing=available_link_config(original,discover_adapters())
    notifications=AdapterNotifications()
    node=Node((ROOT/config['key_file']).read_bytes(),'client',bytes.fromhex(config['session']),
              [tuple(b) for b in config['bind']],tuple(config['peer']),
              interface_indices=config['interface_indices'],path_availability=config['path_availability'],
              bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.1).start()
    report=dict(scope='Real VPS, simulated socket removal/rebind; no physical DHCP/USB changes',
                peer=config['peer'],unavailable_links=missing,windows_notification_registrations=len(notifications.handles))
    try:
        wait(lambda:any(p['healthy'] for p in node.stats()['paths']))
        prefix=node._prefix;old=node.addresses
        report['before_ms']=echo(node)
        node.update_client_paths([tuple(b) for b in config['bind']],config['interface_indices'],[False]*len(config['bind']))
        assert not any(p['available'] for p in node.stats()['paths'])
        assert node.send(b'offline',True)==0
        node.update_client_paths([tuple(b) for b in config['bind']],config['interface_indices'],config['path_availability'])
        wait(lambda:any(p['healthy'] for p in node.stats()['paths']))
        report['after_ms']=echo(node)
        report.update(same_encryption_session=node._prefix==prefix,local_endpoints_before=old,
                      local_endpoints_after=node.addresses,path_rebinds=node.stats()['path_rebinds'],passed=True)
        assert report['same_encryption_session'] and old!=node.addresses
    finally:node.close();notifications.close()
    (ROOT/'evidence/dynamic-links-wan.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if __name__=='__main__':main()
