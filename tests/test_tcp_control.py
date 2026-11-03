import secrets
import struct
import time
import unittest
from gamebond.policy import is_tcp_control
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD

def packet(flags=16,data=b''):
    tcp=struct.pack('!HHIIBBHHH',40000,443,1,1,5<<4,flags,65535,0,0)+data
    return struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),0,0,64,6,0,b'\x0a\x4d\0\x02',b'\x01'*4)+tcp

class TCPControlTests(unittest.TestCase):
    def test_only_valid_ack_only_or_connection_control_bypasses_bulk(self):
        for flags in (16,18,2,17,20):self.assertTrue(is_tcp_control(packet(flags)))
        self.assertFalse(is_tcp_control(packet(16,b'application data')))
        self.assertFalse(is_tcp_control(packet(0)))
        self.assertFalse(is_tcp_control(packet()[:35]))
        fragmented=bytearray(packet());fragmented[6:8]=b'\x20\0'
        self.assertFalse(is_tcp_control(bytes(fragmented)))

    def test_ack_uses_one_immediate_copy_without_bulk_window_or_flow_sequence(self):
        key,session=secrets.token_bytes(32),secrets.token_bytes(16)
        opts=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.03,path_timeout=.5)
        server=Node(key,'server',session,[('127.0.0.1',0)],**opts).start()
        client=Node(key,'client',session,[('127.0.0.1',0)]*2,server.addresses[0],**opts).start()
        try:
            deadline=time.monotonic()+3
            while not all(p['healthy'] for p in client.stats()['paths']):
                if time.monotonic()>deadline:self.fail('Handshake timeout')
                time.sleep(.005)
            with client._lock:
                for path in client._paths.values():path.budget.next_send=time.perf_counter()+10
            start=time.monotonic();ack=packet()
            self.assertEqual(client.send(ack,False,'same TCP flow'),1)
            self.assertEqual(server.recv(1),ack)
            self.assertLess(time.monotonic()-start,.1)
            self.assertEqual(client.stats()['tcp_control_tx_packets'],1)
            self.assertEqual(client.stats()['bonded_packets'],0)
            self.assertEqual(client.stats()['striped_flows'],0)
            self.assertEqual(server.stats()['reorder']['flows'],0)
        finally:client.close();server.close()
