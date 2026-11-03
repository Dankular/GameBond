import math
import secrets
import socket
import struct
import time
import unittest
from gamebond.adaptive_qos import AdaptiveQoS,QoSSettings,mark_dscp,profile_policies
from gamebond.policy import Classifier,parse_packet
from gamebond.transport import Node,OVERHEAD,BOND_OVERHEAD

def udp(source='10.77.0.2',destination='1.1.1.1',sport=40000,dport=443):
    payload=struct.pack('!HHHH',sport,dport,12,0)+b'quic'
    return struct.pack('!BBHHHBBH4s4s',0x45,3,32,1,0,64,17,0,socket.inet_aton(source),socket.inet_aton(destination))+payload

def path(slot,jitter=1,expired=0,acked=100,healthy=True,settled=0):
    return dict(slot=slot,local=['127.0.0.1',slot],remote=['127.0.0.1',1],healthy=healthy,
                rtt_ms=30+slot,rtt_jitter_ms=jitter,bonding=dict(expired_packets=expired,acked_packets=acked,queue_delay_ms=0,delivered_bytes=acked*100,settled_loss_ratio=settled))

class AdaptiveQoSTests(unittest.TestCase):
    def test_general_quic_stays_bulk_even_when_links_are_poor(self):
        qos=AdaptiveQoS();classifier=Classifier(profile_policies())
        qos.observe(dict(paths=[path(0,20),path(1,21)]))
        classification=qos.classify(classifier.classify(udp()))
        self.assertEqual(classification.dscp,0)
        self.assertEqual(qos.transmission(classification,1280),(False,False))
        game=classifier.classify(mark_dscp(udp(),46))
        self.assertTrue(qos.classify(game,'automatic').policy.replicate)
        self.assertFalse(qos.classify(game,'bulk').policy.priority)
        selected=qos.classify(classification,'stream')
        self.assertEqual(qos.transmission(selected,1280),(True,True))

    def test_loss_triggers_bounded_redundancy_and_clean_recovery_has_hysteresis(self):
        now=[0.];qos=AdaptiveQoS(clock=lambda:now[0]);classifier=Classifier(profile_policies())
        call=qos.classify(classifier.classify(udp()),'call')
        qos.observe(dict(paths=[path(0),path(1)]))
        self.assertEqual(qos.transmission(call,1280),(True,False))
        now[0]=1;qos.observe(dict(paths=[path(0,expired=4,acked=196,settled=.04),path(1,acked=200)]))
        self.assertEqual(qos.transmission(call,1280),(True,True))
        self.assertIn('measured_loss',qos.stats()['redundancy']['call']['reason'])
        for _ in range(10):qos.transmission(call,1280)
        self.assertGreater(qos.stats()['counters']['duplicate_budget_limited'],0)
        now[0]=2;qos.observe(dict(paths=[path(0,expired=4,acked=296),path(1,acked=300)]))
        self.assertEqual(qos.transmission(call,1280),(True,True))
        now[0]=4.1;qos.observe(dict(paths=[path(0,expired=4,acked=396),path(1,acked=400)]))
        self.assertEqual(qos.transmission(call,1280),(True,False))
        qos.observe(dict(paths=[path(0,30),path(1,30,healthy=False)]))
        self.assertEqual(qos.transmission(call,1280),(True,False))

    def test_profile_marker_teaches_return_flow_and_preserves_ecn_and_checksum(self):
        qos=AdaptiveQoS();classifier=Classifier(profile_policies())
        packet=mark_dscp(udp(),26);info=parse_packet(packet)
        self.assertEqual(info.dscp,26);self.assertEqual(packet[1]&3,3)
        total=sum(struct.unpack('!10H',packet[:20]))
        while total>>16:total=(total&65535)+(total>>16)
        self.assertEqual(total,65535)
        classifier.classify(packet)
        response=udp('1.1.1.1','10.77.0.2',443,40000)
        classified=qos.classify(classifier.classify(response))
        self.assertEqual(classified.dscp,26);self.assertTrue(classified.policy.priority)
        self.assertEqual(qos.classify(classified,'bulk').dscp,0)

    def test_settings_and_sampling_are_bounded(self):
        for settings in (dict(loss_threshold=math.nan),dict(duplicate_mbps=-1),dict(enabled=1),dict(call_deadline_ms=0)):
            with self.assertRaises(ValueError):QoSSettings(**settings)
        now=[0.];qos=AdaptiveQoS(clock=lambda:now[0]);calls=[]
        def stats():calls.append(1);return dict(paths=[])
        for _ in range(100):qos.refresh(stats)
        self.assertEqual(len(calls),1)
        now[0]=.6;qos.refresh(stats);self.assertEqual(len(calls),2)

    def test_urgent_single_copy_is_not_striped_or_blocked_behind_bulk_window(self):
        key,session=secrets.token_bytes(32),secrets.token_bytes(16)
        options=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.02,path_timeout=.3)
        server=Node(key,'server',session,[('127.0.0.1',0)],**options).start()
        client=Node(key,'client',session,[('127.0.0.1',0)]*2,server.addresses[0],**options).start()
        try:
            deadline=time.monotonic()+3
            while not all(p['healthy'] for p in client.stats()['paths']):
                if time.monotonic()>deadline:self.fail('Handshake timeout')
                time.sleep(.005)
            with client._lock:
                for p in client._paths.values():p.budget.next_send=time.perf_counter()+10
            started=time.monotonic()
            self.assertEqual(client.send(b'interactive',False,'call',urgent=True),1)
            self.assertEqual(server.recv(1),b'interactive')
            self.assertLess(time.monotonic()-started,.2)
            self.assertEqual(client.stats()['bonded_packets'],0)
            self.assertEqual(client.stats()['priority_tx_packets'],1)
        finally:client.close();server.close()
