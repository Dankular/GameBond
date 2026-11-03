"""Real UDP path lifecycle without changing host adapters or routes."""
import secrets
import time
import unittest
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD

def wait(predicate):
    deadline=time.monotonic()+4
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.005)
    raise AssertionError('Path lifecycle timed out')

class PathRebindingTests(unittest.TestCase):
    def test_disconnect_address_change_and_reconnect_preserve_other_socket_and_session(self):
        key,session=secrets.token_bytes(32),secrets.token_bytes(16)
        options=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.02,path_timeout=.2)
        server=Node(key,'server',session,[('127.0.0.1',0)],**options).start()
        client=Node(key,'client',session,[('127.0.0.1',0)]*2,server.addresses[0],path_availability=[True,False],**options).start()
        try:
            wait(lambda:client.stats()['paths'][0]['healthy'])
            prefix=client._prefix;first=client._sockets[0]
            self.assertFalse(client.stats()['paths'][1]['available'])
            self.assertEqual(client.update_client_paths([('127.0.0.1',0),('127.0.0.2',0)],available=[True,True]),[])
            wait(lambda:all(p['healthy'] for p in client.stats()['paths']))
            self.assertIs(client._sockets[0],first)
            second=client._sockets[1]
            client.update_client_paths([('127.0.0.1',0),('127.0.0.2',0)],available=[True,False])
            self.assertFalse(client.stats()['paths'][1]['available'])
            self.assertIs(client._sockets[0],first)
            for sender,receiver in ((client,server),(server,client)):
                self.assertGreater(sender.send(b'still connected',True),0)
                self.assertEqual(receiver.recv(1),b'still connected')
            client.update_client_paths([('127.0.0.1',0),('127.0.0.3',0)],available=[True,True])
            wait(lambda:all(p['healthy'] for p in client.stats()['paths']))
            self.assertIsNot(client._sockets[1],second)
            self.assertIs(client._sockets[0],first);self.assertEqual(client._prefix,prefix)
            self.assertTrue(client._thread.is_alive())
            # All links can disappear, then return without restarting capture/session.
            client.update_client_paths([('127.0.0.1',0),('127.0.0.3',0)],available=[False,False])
            self.assertEqual(client.send(b'offline',True),0)
            client.update_client_paths([('127.0.0.1',0),('127.0.0.4',0)],available=[True,True])
            wait(lambda:all(p['healthy'] for p in client.stats()['paths']))
            self.assertEqual(client.send(b'recovered',True),2)
            self.assertEqual(server.recv(1),b'recovered')
        finally:client.close();server.close()
