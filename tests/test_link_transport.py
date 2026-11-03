import queue
import secrets
import time
import unittest

from gamebond.transport import Node, OVERHEAD, BOND_OVERHEAD, HEADER, DATA, STRIPED, LINK_POLICY
from gamebond.link_policy import LinkPolicy, operational_state, POLICY_HEADER


def state(role='primary',rate=0,blocked=False):
    result=operational_state(LinkPolicy(role=role,upload_mbps=rate,download_mbps=rate),dict(daily_bytes=0,monthly_bytes=0))
    result['blocked']=blocked or result['blocked'];return result


def wait(predicate,seconds=3):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.005)
    raise AssertionError('Link policy condition timed out')


class LinkTransportTests(unittest.TestCase):
    def setUp(self):self.nodes=[]
    def tearDown(self):
        for node in reversed(self.nodes):node.close()

    def pair(self,states):
        key,session=secrets.token_bytes(32),secrets.token_bytes(16)
        options=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.05,path_timeout=.3,
                     initial_rate_mbps=20,max_rate_mbps=20)
        server=Node(key,'server',session,[('127.0.0.1',0)],**options).start();self.nodes.append(server)
        client=Node(key,'client',session,[('127.0.0.1',0)]*2,server.addresses[0],link_states=states,**options).start();self.nodes.append(client)
        wait(lambda:all(p['policy_confirmed'] for p in client.stats()['paths'] if p['enabled']))
        return client,server

    def test_primary_backup_roles_and_failure_are_enforced_in_both_directions(self):
        client,server=self.pair([state(),state('backup')])
        addresses=tuple(client.addresses)
        used=[[],[]];originals=[client._write,server._write]
        for i,node in enumerate((client,server)):
            def write(packet,path,i=i):
                index=path.socket_index if i==0 else addresses.index(path.endpoint)
                if HEADER.unpack_from(packet)[3] in (DATA,STRIPED):used[i].append(index)
                return originals[i](packet,path)
            node._write=write
        for sender,receiver in ((client,server),(server,client)):
            for _ in range(8):self.assertEqual(sender.send(b'bulk',False,'flow'),1)
            self.assertEqual([receiver.recv(1) for _ in range(8)],[b'bulk']*8)
        self.assertEqual([set(v) for v in used],[{0},{0}])
        for i,node in enumerate((client,server)):
            def blackhole(packet,path,i=i):
                index=path.socket_index if i==0 else addresses.index(path.endpoint)
                if index==0:return False
                return originals[i](packet,path)
            node._write=blackhole
        wait(lambda:not client.stats()['paths'][0]['healthy'],2)
        for sender,receiver in ((client,server),(server,client)):
            wait(lambda:all(time.perf_counter()-p.last_rx>.3 for p in sender._paths.values() if
                           (p.socket_index==0 if sender is client else p.endpoint==client.addresses[0])),2)
            self.assertEqual(sender.send(b'backup works',False,'flow'),1)
            self.assertEqual(receiver.recv(1),b'backup works')

    def test_never_does_not_even_authenticate_and_live_change_reaches_server(self):
        client,server=self.pair([state(),state('never')])
        self.assertEqual(client.stats()['paths'][1]['tx_bytes'],0)
        self.assertEqual(len(server.stats()['paths']),1)
        client.set_link_states([state(blocked=True),state()])
        wait(lambda:client.stats()['paths'][1]['policy_confirmed'])
        wait(lambda:any(p.link_state and p.link_state['blocked'] for p in server._paths.values()))
        for sender,receiver in ((client,server),(server,client)):
            self.assertEqual(sender.send(b'new policy',False,'flow'),1)
            self.assertEqual(receiver.recv(1),b'new policy')

    def test_configured_rate_ceiling_includes_wire_overhead_both_directions(self):
        client,server=self.pair([state(rate=.25),state('never')])
        for sender,receiver in ((client,server),(server,client)):
            path=next(p for p in sender._paths.values() if p.link_state and p.link_state['role']=='primary')
            start=time.perf_counter();before=path.tx_bytes+28*path.transmitted
            for _ in range(30):self.assertEqual(sender.send(b'x'*1000,False,'one'),1)
            for _ in range(30):self.assertEqual(receiver.recv(2),b'x'*1000)
            elapsed=time.perf_counter()-start;wire=path.tx_bytes+28*path.transmitted-before
            self.assertLessEqual(wire,.25*125000*elapsed+2800+100)
            self.assertGreaterEqual(elapsed,.8)

    def test_authenticated_invalid_policy_is_rejected(self):
        client,server=self.pair([state(),state('never')])
        before=server.stats()['malformed']
        packet=client._encode(LINK_POLICY,POLICY_HEADER.pack(999,99,0,0,0))
        server._receive(0,packet,client.addresses[0])
        self.assertEqual(server.stats()['malformed'],before+1)
        self.assertEqual(next(iter(server._paths.values())).link_state['role'],'primary')
