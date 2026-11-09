"""Multi-uplink configuration and real-socket bonding regressions."""
import json
import queue
import secrets
import struct
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from gamebond import app
from gamebond.transport import Node,HEADER,STRIPED
from gamebond.widget_data import save_selection
from gamebond.userspace import available_link_config


def config(count,shared=False):
    return dict(role='client',bind=[['192.168.1.2' if shared else f'192.168.{i+1}.2',0] for i in range(count)],
        interface_indices=list(range(10,10+count)),interface_ids=[f'{{{i+1:08x}-1111-1111-1111-{i+1:012x}}}' for i in range(count)],
        gateways=['192.168.1.1' if shared else f'192.168.{i+1}.1' for i in range(count)],
        interface_names=[f'Starlink {i+1}' for i in range(count)],
        peer=['203.0.113.1',4433],session='12'*16,client_tunnel_ip='10.77.0.2',
        bonding_mode=True,redundant_mode=False,app_rules={})


def links(c):
    return [dict(index=index,id=c['interface_ids'][i],name=c['interface_names'][i],up=True,
        addresses=[c['bind'][i][0]],gateway=c['gateways'][i]) for i,index in enumerate(c['interface_indices'])]


class MultiLinkConfigTests(unittest.TestCase):
    def validate(self,c,offline=False,platform='nt'):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(c))
            with patch.object(app,'os',types.SimpleNamespace(name=platform)):
                return app.load_config(path,allow_unavailable_links=offline)

    def test_one_two_three_four_and_eight_link_configs(self):
        for count in (1,2,3,4,8):
            with self.subTest(count=count):self.assertEqual(len(self.validate(config(count))['bind']),count)

    def test_count_and_identity_errors_are_rejected(self):
        for count in (0,9):
            with self.subTest(count=count),self.assertRaises(ValueError):self.validate(config(count))
        c=config(3);c['interface_indices'][2]=c['interface_indices'][0]
        with self.assertRaises(ValueError):self.validate(c)
        c=config(3);c['interface_ids'][2]=c['interface_ids'][0]
        with self.assertRaises(ValueError):self.validate(c)

    def test_overlapping_lans_require_pinned_stable_windows_adapters(self):
        c=config(3,shared=True);self.assertEqual(len(self.validate(c)['bind']),3)
        with self.assertRaises(ValueError):self.validate(c,platform='posix')
        c.pop('interface_ids')
        with self.assertRaises(ValueError):self.validate(c)

    def test_shared_subnet_selection_requires_identities_before_saving(self):
        c=config(3,shared=True);inventory=links(c)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(c))
            self.assertEqual(len(self.validate(save_selection(c['interface_indices'],path,inventory))['bind']),3)
            before=path.read_bytes()
            for row in inventory:row['id']=''
            with self.assertRaises(ValueError):save_selection(c['interface_indices'],path,inventory)
            self.assertEqual(path.read_bytes(),before)

    def test_multiple_offline_slots_keep_identity_and_rebind(self):
        c=config(4);inventory=links(c)
        c['bind'][1]=['0.0.0.0',0];c['bind'][3]=['0.0.0.0',0]
        loaded=self.validate(c,offline=True)
        inventory[1].update(up=False,addresses=[],gateway='')
        inventory[3].update(up=False,addresses=[],gateway='')
        resolved,missing=available_link_config(loaded,inventory)
        self.assertEqual(resolved['path_availability'],[True,False,True,False]);self.assertEqual(len(missing),2)
        inventory[3].update(up=True,index=103,addresses=['192.168.4.8'],gateway='192.168.4.1')
        resolved,missing=available_link_config(loaded,inventory)
        self.assertEqual(resolved['interface_indices'][3],103);self.assertEqual(resolved['bind'][3][0],'192.168.4.8')
        self.assertEqual(resolved['path_availability'],[True,False,True,True])

    def test_selection_round_trips_eight_links_and_preserves_other_settings(self):
        c=config(8);inventory=links(c);c['capture_mode']='selected';c['link_policies']={'10':{'role':'backup'}}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(c))
            saved=save_selection(c['interface_indices'],path,inventory)
            for field in ('session','peer','capture_mode','link_policies'):self.assertEqual(saved[field],c[field])
            self.assertEqual(len(self.validate(saved)['bind']),8)
            original=path.read_bytes()
            with self.assertRaises(ValueError):save_selection(list(range(10,19)),path,inventory)
            self.assertEqual(path.read_bytes(),original)

    def test_duplicate_adapter_guid_cannot_be_selected_twice(self):
        c=config(3);inventory=links(c);inventory[2]['id']=inventory[0]['id']
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(c))
            with self.assertRaises(ValueError):save_selection(c['interface_indices'],path,inventory)


def wait_for(predicate,timeout=4):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.005)
    raise AssertionError('Multi-link readiness timed out')


class MultiLinkTransportTests(unittest.TestCase):
    def test_three_and_eight_paths_stripe_both_directions_and_survive_failover(self):
        for count in (3,8):
            with self.subTest(paths=count):self.exercise(count)

    def exercise(self,count):
        key,session=secrets.token_bytes(32),secrets.token_bytes(16)
        options=dict(bonding_mode=True,probe_interval=.03,path_timeout=.3,initial_rate_mbps=50,max_rate_mbps=100)
        server=Node(key,'server',session,[('127.0.0.1',0)],**options).start()
        client=Node(key,'client',session,[('127.0.0.1',0)]*count,server.addresses[0],**options).start()
        try:
            wait_for(lambda:len(server.stats()['paths'])==count and all(p['healthy'] and p['ready'] and p['rtt_ms'] is not None and p['rtt_ms']>0 for p in client.stats()['paths'])
                     and all(p['healthy'] and p['ready'] and p['rtt_ms'] is not None and p['rtt_ms']>0 for p in server.stats()['paths']))
            upload=[0]*count;download={endpoint:0 for endpoint in client.addresses}
            client_write,server_write=client._write,server._write
            def write_upload(frame,path):
                ok=client_write(frame,path)
                if ok and HEADER.unpack_from(frame)[3]==STRIPED:upload[path.socket_index]+=1
                return ok
            def write_download(frame,path):
                ok=server_write(frame,path)
                if ok and HEADER.unpack_from(frame)[3]==STRIPED:download[path.endpoint]+=1
                return ok
            client._write,server._write=write_upload,write_download
            packets=[struct.pack('!I',i)+b'x'*96 for i in range(count*20)]
            for packet in packets:self.assertEqual(client.send(packet,replicate=False,flow_id='upload'),1)
            received=[server.recv(2) for _ in packets]
            self.assertEqual(len(set(received)),len(packets));self.assertEqual(set(received),set(packets))
            self.assertTrue(all(upload),upload)
            for packet in packets:self.assertEqual(server.send(packet,replicate=False,flow_id='download'),1)
            received=[client.recv(2) for _ in packets]
            self.assertEqual(len(set(received)),len(packets));self.assertEqual(set(received),set(packets))
            self.assertTrue(all(download.values()),download)
            self.assertEqual(client.send(b'gameplay',replicate=True,urgent=True),count)
            self.assertEqual(server.recv(2),b'gameplay')
            wait_for(lambda:server.stats()['duplicates']>=count-1)
            with self.assertRaises(queue.Empty):server.recv(.03)
            client.update_client_paths([('127.0.0.1',0)]*count,available=[False]*(count-1)+[True])
            wait_for(lambda:sum(p['healthy'] for p in server.stats()['paths'])==1)
            self.assertEqual(client.send(b'upload after outage',replicate=False,flow_id='failover'),1)
            self.assertEqual(server.recv(2),b'upload after outage')
            self.assertEqual(server.send(b'download after outage',replicate=False,flow_id='failover'),1)
            self.assertEqual(client.recv(2),b'download after outage')
        finally:client.close();server.close()


if __name__=='__main__':unittest.main()
