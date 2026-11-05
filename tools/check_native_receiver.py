"""Existing Python GB03 client against a loopback-only Go receive harness.

No capture, routes, adapters, VPS processes, or active user tunnel are modified.
This verifies receive interoperability, not a complete native edge or bonding gain.
"""
import json
import argparse
from pathlib import Path
import queue
import secrets
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from gamebond.transport import Node,HEADER,STRIPED,STRIPE_HEADER,PROBE
from gamebond.userspace import live_status

def wait(predicate,seconds=5):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate():return
        time.sleep(.01)
    raise AssertionError('Native receive interoperability timed out')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bonded',action='store_true');parser.add_argument('--repair',action='store_true');parser.add_argument('--policies',action='store_true');parser.add_argument('--paths',type=int,choices=range(2,9),default=2);args=parser.parse_args()
    if args.repair and not args.bonded:parser.error('--repair requires --bonded')
    if args.policies and not args.bonded:parser.error('--policies requires --bonded')
    before=live_status();key=secrets.token_bytes(32);session=secrets.token_bytes(16)
    process=subprocess.Popen([str(ROOT/'build/gamebond-native-receiver-probe.exe')],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    client=None
    try:
        process.stdin.write(json.dumps(dict(key=key.hex(),session=session.hex(),bonded=args.bonded))+'\n');process.stdin.flush()
        ready=json.loads(process.stdout.readline());address,port=ready['address'].rsplit(':',1)
        def state(role='primary',blocked=False):return dict(role=role,blocked=blocked,upload_mbps=2,download_mbps=2)
        client=Node(key,'client',session,[('127.0.0.1',0)]*args.paths,peer=(address,int(port)),bonding_mode=True,
            probe_interval=.025,path_timeout=.3,initial_rate_mbps=10,max_rate_mbps=10,
            link_states=[state() for _ in range(args.paths)] if args.policies else None).start()
        wait(lambda:all(p['healthy'] for p in client.stats()['paths']))
        if args.policies:wait(lambda:all(p['policy_confirmed'] for p in client.stats()['paths']))
        dropped=dict(upload=0,download=0)
        down_by_slot=[0]*args.paths;up_by_slot=[0]*args.paths;server_probe_slots=set()
        base_write,base_receive=client._write,client._receive
        def observed_write(frame,path,**kwargs):
            success=base_write(frame,path,**kwargs)
            if success and frame[36]==STRIPED:up_by_slot[path.socket_index]+=1
            return success
        def observed_receive(index,frame,endpoint,received_at=None):
            if frame[36]==PROBE:server_probe_slots.add(index)
            if frame[36]==STRIPED:down_by_slot[index]+=1
            return base_receive(index,frame,endpoint,received_at)
        client._write,client._receive=observed_write,observed_receive
        if args.repair:
            original_write,original_receive=client._write,client._receive
            def write(frame,path,**kwargs):
                if frame[36]==STRIPED and not dropped['upload']:
                    sequence=HEADER.unpack_from(frame)[-1]
                    body=client._tx.decrypt(b'\0'*4+sequence.to_bytes(8,'big'),frame[HEADER.size:],frame[:HEADER.size])
                    if STRIPE_HEADER.unpack_from(body)[1]==7:
                        dropped['upload']+=1;return True
                return original_write(frame,path,**kwargs)
            def receive(index,frame,endpoint,received_at=None):
                if frame[36]==STRIPED and not dropped['download']:
                    _,_,prefix,_,sequence=HEADER.unpack_from(frame)
                    body=client._cipher(prefix,'server').decrypt(b'\0'*4+sequence.to_bytes(8,'big'),frame[HEADER.size:],frame[:HEADER.size])
                    if STRIPE_HEADER.unpack_from(body)[1]==17:
                        dropped['download']+=1;return
                return original_receive(index,frame,endpoint,received_at)
            client._write,client._receive=write,receive
        # Wait for directional RTT discovery on every link before comparing bulk use.
        if args.bonded:wait(lambda:len(server_probe_slots)==args.paths)
        def payload(number):
            if not args.repair:return struct.pack('!Q',number)+bytes([number%251])*992
            packet=bytearray(1000);packet[0]=0x45;packet[2:4]=struct.pack('!H',1000);packet[9]=6
            packet[12:20]=bytes([10,77,0,2,1,1,1,1]);packet[20:24]=struct.pack('!HH',1234,443);packet[32]=0x50;packet[33]=0x18
            packet[40:48]=struct.pack('!Q',number);packet[48:]=bytes([number%251])*952
            return bytes(packet)
        received=[]
        # Keep the test below the deliberately bounded receive inbox; verify
        # independent chunks of one continuous flow and both path counters.
        for batch in range(10):
            for number in range(batch*40,(batch+1)*40):
                assert client.send(payload(number),replicate=False,flow_id='native-interop')==1
            for _ in range(40):received.append(client.recv(3))
        expected=[payload(n) for n in range(400)]
        assert len(received)==len(set(received))==400 and set(received)==set(expected)
        if not args.repair:assert received==expected
        assert client.send(b'replicated-control',replicate=True)==args.paths
        assert client.recv(2)==b'replicated-control'
        try:client.recv(.12)
        except queue.Empty:pass
        else:raise AssertionError('Replicated payload delivered twice')
        roles=[];role_packets=0
        if args.policies:
            for name,states,slot in [('primary_with_backup',[state()]+[state('backup') for _ in range(args.paths-1)],0),
                    ('blocked_primary_uses_backup',[state(blocked=True),state('backup')]+[state('never') for _ in range(args.paths-2)],1)]:
                client.set_link_states(states)
                wait(lambda:all(p['policy_confirmed'] for p in client.stats()['paths']))
                initial_up,initial_down=up_by_slot[:],down_by_slot[:]
                expected_role=[payload(500+role_packets+n) for n in range(20)]
                for packet in expected_role:assert client.send(packet,replicate=False,flow_id='native-roles')==1
                returned=[client.recv(3) for _ in range(20)]
                assert returned==expected_role
                up=[a-b for a,b in zip(up_by_slot,initial_up)];down=[a-b for a,b in zip(down_by_slot,initial_down)]
                assert up[slot]==20 and down[slot]==20 and all(value==0 for index,value in enumerate(up) if index!=slot) and all(value==0 for index,value in enumerate(down) if index!=slot)
                roles.append(dict(case=name,upload=up,download=down));role_packets+=20
        wait(lambda:client.stats()['feedback_received']>0)
        stats=client.stats()
        assert all(p['bonding']['sent_packets']>0 for p in stats['paths'])
        assert stats['auth_failures']==0 and stats['receive_drops']==0
        client.close();client=None;process.stdin.write('x');process.stdin.flush()
        report=json.loads(process.stdout.readline());assert process.wait(5)==0
        assert report['receiver']['PayloadPackets']==401+role_packets
        assert report['receiver']['Duplicates']>=1
        if args.bonded:
            assert report['sender']['StripedPackets']==401+role_packets
            assert all(p['Budget']['sent_packets']>0 and p['Budget']['delivered_bytes']>0 for p in report['paths'])
            assert report['transmit_queue']['Expired']==0 and report['transmit_queue']['Rejected']==0
        if args.repair:
            assert dropped==dict(upload=1,download=1)
            assert stats['repair_packets']>=1 and stats['repair_requests']>=1
            assert report['sender']['RepairCopies']>=1 and report['sender']['RepairRequests']>=1
        after=live_status();assert (before or {}).get('pid')==(after or {}).get('pid')
        evidence=dict(scope=('Real UDP loopback; bidirectional Python/Go single-flow striping and pacing; no TUN/VPS/physical aggregation claim' if args.bonded else 'Real UDP loopback; Python client to Go receive half; no native transmit pacing or TUN/VPS claim'),
            selected_links=args.paths,payload_packets=400,payload_bytes=sum(map(len,received)),ordered=received==expected,replica_deduplicated=True,injected_test_drops=dropped,
            python_repairs=dict(copies=stats.get('repair_packets',0),requests=stats.get('repair_requests',0)),
            role_cases=roles,configured_wire_limits_mbps=2 if args.policies else None,
            feedback_received=stats['feedback_received'],per_path_sent=[p['bonding']['sent_packets'] for p in stats['paths']],
            native=report,live_client_pid_unchanged=(after or {}).get('pid'))
        target='evidence/native-policies-interop.json' if args.policies else ('evidence/native-repair-interop.json' if args.repair else ('evidence/native-bonded-interop.json' if args.bonded else 'evidence/native-receiver-interop.json'))
        if args.paths!=2:target=target.replace('.json',f'-{args.paths}links.json')
        (ROOT/target).write_text(json.dumps(evidence,indent=2)+'\n')
        print(json.dumps(evidence,indent=2))
    finally:
        if client:client.close()
        if process.poll() is None:
            try:process.stdin.close();process.wait(5)
            except (OSError,subprocess.TimeoutExpired):process.kill();process.wait(5)
        process.stdout.close();process.stderr.close()

if __name__=='__main__':main()
