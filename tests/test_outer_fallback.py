"""UDP-blocked simulation on isolated loopback sockets; no host firewall changes."""
from pathlib import Path
import json
import queue
import secrets
import socket
import tempfile
import time
import unittest
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD
from gamebond.stream_carrier import CarrierRelay
from test_stream_carrier import certificate

def wait(predicate,seconds=6):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.01)
    raise AssertionError('Outer fallback condition timed out')

class OuterFallbackTests(unittest.TestCase):
    def test_udp_blocked_tls_and_https_authenticate_and_recover_to_udp(self):
        for mode in ('tcp','tls','https'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                cert,context=certificate(directory);key,session=secrets.token_bytes(32),secrets.token_bytes(16)
                options=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.03,path_timeout=.4)
                server=Node(key,'server',session,[('127.0.0.1',0)],**options).start()
                relay=CarrierRelay(('127.0.0.1',0),server.addresses[0],key,session,mode=mode,context=None if mode=='tcp' else context).start()
                client=Node(key,'client',session,[('127.0.0.1',0)],server.addresses[0],outer_transport=dict(
                    endpoints=[dict(mode=mode,port=relay.address[1],ca_file=str(cert))],fallback_after=.1,recovery_interval=.2),**options)
                carrier=client._sockets[0];original=carrier.raw
                # Simulate outbound UDP filtering while preserving real stream TCP.
                class BlockedUDP:
                    def __init__(self,raw):self.raw=raw;self.blocked=True;self.drop_incoming=False
                    def sendto(self,data,endpoint):
                        if self.blocked:return len(data)
                        return self.raw.sendto(data,endpoint)
                    def __getattr__(self,name):return getattr(self.raw,name)
                    def fileno(self):return self.raw.fileno()
                    def recvfrom(self,size):
                        data=self.raw.recvfrom(size)
                        if self.drop_incoming:raise BlockingIOError('Simulated inbound-only UDP filter')
                        return data
                blocked=BlockedUDP(original);carrier.raw=blocked
                client.start()
                try:
                    wait(lambda:client.stats()['paths'][0]['healthy'])
                    self.assertEqual(carrier.mode,mode)
                    for sender,receiver in ((client,server),(server,client)):
                        self.assertEqual(sender.send(b'fallback data',False,'bulk'),1)
                        self.assertEqual(receiver.recv(1),b'fallback data')
                    prefix=client._prefix;blocked.blocked=False
                    wait(lambda:carrier.mode=='udp' and client.stats()['paths'][0]['healthy'])
                    self.assertEqual(client._prefix,prefix)
                    client.send(b'recovered UDP',True)
                    self.assertEqual(server.recv(1),b'recovered UDP')
                    self.assertGreater(carrier.stats()['counters']['udp_recoveries'],0)
                    # An outbound-only recovery probe cannot move the server away
                    # from the working stream while incoming UDP remains blocked.
                    blocked.drop_incoming=True
                    wait(lambda:carrier.mode==mode and carrier.stats()['peer_confirmed'])
                    for _ in range(3):
                        server.send(b'inbound UDP still blocked',True)
                        try:received=client.recv(1)
                        except queue.Empty:
                            self.fail(json.dumps(dict(carrier=carrier.stats(),relay=relay.stats(),
                                client={k:v for k,v in client.stats().items() if k!='paths'},
                                server_paths=[{k:p[k] for k in ('remote','ready','healthy','tx_bytes','rx_bytes')} for p in server.stats()['paths']]),indent=2))
                        self.assertEqual(received,b'inbound UDP still blocked')
                        time.sleep(.21)
                    self.assertEqual(carrier.mode,mode)
                    blocked.drop_incoming=False
                    wait(lambda:carrier.mode=='udp' and client.stats()['paths'][0]['healthy'])
                finally:client.close();relay.close();server.close()

    def test_invalid_certificate_does_not_silently_downgrade_to_tcp(self):
        with tempfile.TemporaryDirectory() as directory:
            cert,context=certificate(directory);key,session=secrets.token_bytes(32),secrets.token_bytes(16)
            options=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.03,path_timeout=.4)
            server=Node(key,'server',session,[('127.0.0.1',0)],**options).start()
            relay=CarrierRelay(('127.0.0.1',0),server.addresses[0],key,session,context=context).start()
            client=Node(key,'client',session,[('127.0.0.1',0)],('127.0.0.1',1),outer_transport=dict(
                endpoints=[dict(mode='tls',port=relay.address[1],ca_file=str(cert),server_name='wrong.example')],fallback_after=.1),**options).start()
            try:
                wait(lambda:client._sockets[0].stats()['counters'].get('connection_errors',0)>0)
                self.assertFalse(client.stats()['paths'][0]['healthy'])
                self.assertEqual(relay.stats().get('authenticated',0),0)
                self.assertEqual(client._sockets[0].mode,'udp')
            finally:client.close();relay.close();server.close()
