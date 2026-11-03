import struct
import os
import subprocess
import sys
import unittest
from gamebond.userspace import mark_game_udp
from gamebond.policy import parse_packet
from pathlib import Path
import tempfile
from unittest.mock import MagicMock


class UserspacePolicyTests(unittest.TestCase):
    def test_missing_phone_keeps_available_link_and_saved_selection(self):
        from gamebond.userspace import available_link_config
        config=dict(interface_indices=[25,16],bind=[['192.168.1.93',0],['172.20.10.2',0]],gateways=['192.168.1.1','172.20.10.1'])
        links=[dict(index=25,name='Starlink',up=True,addresses=['192.168.1.94'],gateway='192.168.1.1'),
               dict(index=16,name='Phone',up=True,addresses=['169.254.1.2'],gateway='')]
        resolved,missing=available_link_config(config,links)
        self.assertEqual(resolved['interface_indices'],[25,16])
        self.assertEqual(resolved['bind'],[['192.168.1.94',0],['0.0.0.0',0]])
        self.assertEqual(resolved['path_availability'],[True,False])
        self.assertEqual(missing[0]['name'],'Phone')
        self.assertEqual(config['interface_indices'],[25,16])
        self.assertEqual(config['bind'][0][0],'192.168.1.93')
        with self.assertRaisesRegex(RuntimeError,'No selected network is available'):
            available_link_config(config,[])

    def test_stable_adapter_identity_follows_new_index_and_dhcp_address(self):
        from gamebond.userspace import available_link_config
        config=dict(interface_indices=[25,16],interface_ids=['{starlink}','{phone}'],
                    bind=[['192.168.1.93',0],['172.20.10.2',0]],gateways=['192.168.1.1','172.20.10.1'])
        links=[dict(index=70,id='{phone}',name='Phone',up=True,addresses=['172.20.10.7'],gateway='172.20.10.1'),
               dict(index=16,id='{different}',name='Other',up=True,addresses=['10.0.0.2'],gateway='10.0.0.1')]
        resolved,missing=available_link_config(config,links)
        self.assertEqual(resolved['interface_indices'],[25,70])
        self.assertEqual(resolved['bind'][1][0],'172.20.10.7')
        self.assertEqual(resolved['path_availability'],[False,True])
        offline,missing=available_link_config(config,[],require_available=False)
        self.assertEqual(offline['path_availability'],[False,False])
    def test_wire_metering_is_persistent_and_cap_blocks_the_peer_policy(self):
        from gamebond.userspace import Runtime
        from gamebond.link_policy import UsageLedger,LinkPolicy
        with tempfile.TemporaryDirectory() as directory:
            runtime=object.__new__(Runtime)
            runtime.usage_ledger=UsageLedger(Path(directory)/'usage.json');runtime.previous_wire={}
            runtime.link_policies={'25':LinkPolicy(daily_bytes=1000)}
            runtime.config=dict(interface_indices=[25],link_policies={'25':{}});runtime.node=MagicMock()
            runtime.last_transport=dict(paths=[dict(interface_index=25,tx_bytes=300,rx_bytes=500,wire_tx_bytes=400,metered_download_bytes=700)])
            runtime.meter_links()
            self.assertEqual(runtime.link_usage['25']['daily_bytes'],1100)
            self.assertTrue(runtime.node.set_link_states.call_args.args[0][0]['blocked'])
            runtime.meter_links()
            self.assertEqual(runtime.link_usage['25']['daily_bytes'],1100)
            restored=UsageLedger(Path(directory)/'usage.json')
            self.assertEqual(restored.usage('25',runtime.link_policies['25'])['daily_bytes'],1100)
    @unittest.skipUnless(os.name=='nt','Windows process ownership')
    def test_backend_job_closes_its_child_when_owner_exits(self):
        from gamebond.process_job import ProcessJob
        job=ProcessJob()
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],
                               creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            job.add(child);job.close()
            child.wait(timeout=3)
            self.assertIsNotNone(child.returncode)
        finally:
            job.close()
            if child.poll() is None:child.kill()
            child.wait(timeout=3)
    def test_selected_process_udp_tag_preserves_ecn_payload_and_checksum(self):
        payload=struct.pack('!HHHH',50000,3075,12,0)+b'game'
        header=struct.pack('!BBHHHBBH4s4s',0x45,3,20+len(payload),123,0,64,17,0,
                           b'\x0a\x4d\0\x02',b'\x01\x01\x01\x01')
        packet=header+payload
        tagged=mark_game_udp(packet)
        self.assertEqual(parse_packet(tagged).dscp,46)
        self.assertEqual(tagged[1]&3,3)
        self.assertEqual(tagged[20:],payload)
        total=sum(struct.unpack('!10H',tagged[:20]))
        while total>>16:total=(total&65535)+(total>>16)
        self.assertEqual(total,65535)

    def test_tcp_is_unchanged_and_invalid_header_is_rejected(self):
        packet=bytearray(40);packet[0]=0x45;packet[9]=6
        self.assertEqual(mark_game_udp(bytes(packet)),bytes(packet))
        packet[0]=0x4f;packet[9]=17
        with self.assertRaises(ValueError):mark_game_udp(bytes(packet))

    def test_general_udp_is_not_duplicated_as_gameplay_when_routing_all_apps(self):
        def packet(port):
            udp=struct.pack('!HHHH',50000,port,12,0)+b'data'
            return struct.pack('!BBHHHBBH4s4s',0x45,0,32,0,0,64,17,0,b'\x0a\x4d\0\x02',b'\x01'*4)+udp
        quic=packet(443)
        self.assertEqual(mark_game_udp(quic,[3075]),quic)
        self.assertEqual(parse_packet(mark_game_udp(packet(3075),[3075])).dscp,46)

if __name__=='__main__':unittest.main()
