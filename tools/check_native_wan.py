"""Separate client stack -> native VPS TUN/NAT, preserving the live tunnel."""
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from gamebond.userspace import available_link_config,live_status
from gamebond.windows_adapters import discover_adapters
from stack_peer import StackPeer
from check_outer_wan import probes

def main():
    candidate=json.loads((ROOT/'.runtime/native-stage/candidate.json').read_text());original=json.loads((ROOT/'configs/local-client.json').read_text())
    config,missing=available_link_config(original,discover_adapters());before=live_status()
    node=Node((ROOT/original['key_file']).read_bytes(),'client',bytes.fromhex(candidate['session']),
        [tuple(row) for row in config['bind']],tuple(candidate['peer']),interface_indices=config['interface_indices'],
        path_availability=config['path_availability'],bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD).start()
    stack=None
    try:
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            paths=node.stats()['paths']
            if all(p['healthy'] for p in paths):break
            time.sleep(.05)
        if not any(p['healthy'] for p in node.stats()['paths']):raise RuntimeError('No native candidate path authenticated')
        stack=StackPeer(node,'native-egress')
        result=probes(stack.address)
        if set(result.values())!={candidate['peer'][0]}:raise RuntimeError('Native TCP/UDP exit did not match VPS')
        after=live_status()
        if before:assert after and after['pid']==before['pid'],'Live tunnel changed'
        report=dict(scope='Actual test-owned userspace stack through native Go VPS TUN/NAT; production capture unchanged',
            candidate={key:candidate[key] for key in ('container','id','image','peer','binary_sha256')},egress=result,
            client=node.stats(),stack=dict(stack.metrics),stack_errors=stack.errors,missing_adapters=missing,
            production_client_unchanged=True,production_pid=(after or {}).get('pid'))
        assert not stack.errors
        (ROOT/'evidence/native-edge-wan.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(egress=result,healthy_paths=sum(p['healthy'] for p in report['client']['paths']),production_pid=report['production_pid'])))
    finally:
        if stack:stack.close()
        node.close()

if __name__=='__main__':main()
