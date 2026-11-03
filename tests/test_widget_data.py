import json
from pathlib import Path
import tempfile
import unittest

from gamebond.widget_data import RateSampler, save_selection, TunnelRateSampler, save_link_policies


class WidgetDataTests(unittest.TestCase):
    def test_offline_selected_adapter_keeps_identity_and_resolves_new_address_later(self):
        from gamebond.app import load_config
        from gamebond.userspace import available_link_config
        identities=['{11111111-1111-1111-1111-111111111111}','{22222222-2222-2222-2222-222222222222}']
        links=[dict(index=25,id=identities[0],name='Starlink',up=True,addresses=['192.168.1.93'],gateway='192.168.1.1'),
               dict(index=16,id=identities[1],name='Phone',up=False,addresses=[],gateway='')]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json'
            original=dict(role='client',session='12'*16,peer=['203.0.113.1',4433],interface_indices=[25,16],client_tunnel_ip='10.77.0.2')
            path.write_text(json.dumps(original));saved=save_selection([25,16],path,links)
            self.assertEqual(saved['bind'][1],['0.0.0.0',0]);self.assertEqual(saved['interface_ids'],identities)
            validated=load_config(path,allow_unavailable_links=True)
            resolved,missing=available_link_config(validated,links)
            self.assertEqual(resolved['path_availability'],[True,False]);self.assertEqual(len(missing),1)
            with self.assertRaises(ValueError):load_config(path)
            links[1].update(up=True,index=47,addresses=['172.20.10.7'],gateway='172.20.10.1')
            resolved,missing=available_link_config(validated,links)
            self.assertEqual(resolved['bind'][1][0],'172.20.10.7');self.assertEqual(resolved['interface_indices'],[25,47]);self.assertEqual(missing,[])

    def test_link_controls_save_preserves_session_and_rejects_all_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json'
            original=dict(interface_indices=[25,16],session='keep',capture_mode='all')
            path.write_text(json.dumps(original))
            saved=save_link_policies({'25':dict(role='primary'),'16':dict(role='backup',daily_bytes=10**9)},path)
            self.assertEqual(saved['session'],'keep');self.assertEqual(saved['capture_mode'],'all')
            self.assertEqual(saved['link_policies']['16']['role'],'backup')
            before=path.read_bytes()
            with self.assertRaises(ValueError):save_link_policies({'25':dict(role='never'),'16':dict(role='never')},path)
            self.assertEqual(path.read_bytes(),before)

    def test_payload_and_encrypted_counters_remain_separate_and_restart_resets(self):
        sampler=TunnelRateSampler()
        runtime=dict(pid=1,transport=dict(rx_bytes=10000,tx_bytes=10000),application=dict(downloaded_bytes=1000,uploaded_bytes=1000))
        sampler.sample(runtime,1)
        runtime['transport'].update(rx_bytes=14000,tx_bytes=16000)
        runtime['application'].update(downloaded_bytes=2000,uploaded_bytes=2500)
        rates=sampler.sample(runtime,3)
        self.assertEqual(rates['application']['down'],500)
        self.assertEqual(rates['encrypted']['down'],2000)
        runtime['pid']=2
        self.assertEqual(sampler.sample(runtime,4)['application']['down'],0)
        self.assertIsNone(sampler.sample(None,5)['application'])

    def test_rates_use_elapsed_time_and_do_not_count_initial_totals(self):
        sampler=RateSampler()
        first=sampler.sample({'phone':(1000000,2000000)},10)['phone']
        self.assertEqual((first['down'],first['received']),(0,0))
        current=sampler.sample({'phone':(1004000,2002000)},12)['phone']
        self.assertEqual((current['down'],current['up']),(2000,1000))
        self.assertEqual((current['received'],current['sent']),(4000,2000))

    def test_counter_reset_and_adapter_reappearance_create_new_baselines(self):
        sampler=RateSampler()
        sampler.sample({'ethernet':(100,100)},1)
        sampler.sample({'ethernet':(200,200)},2)
        reset=sampler.sample({'ethernet':(0,0)},3)['ethernet']
        self.assertEqual((reset['down'],reset['received']),(0,100))
        sampler.sample({},4)
        returned=sampler.sample({'ethernet':(100000,100000)},5)['ethernet']
        self.assertEqual((returned['down'],returned['received']),(0,100))

    def test_selection_keeps_unrelated_configuration_and_rejects_unusable_links(self):
        links=[dict(index=25,up=True,addresses=['192.168.1.93'],gateway='192.168.1.1'),
               dict(index=16,up=True,addresses=['172.20.10.2'],gateway='172.20.10.1')]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json'
            original=dict(session='keep-this-session',peer=['203.0.113.1',4433],
                          queues={'46':{'priority':True}},dns={'enabled':True})
            path.write_text(json.dumps(original))
            selected=save_selection([16,25],path,links)
            self.assertEqual(selected['interface_indices'],[16,25])
            self.assertEqual(selected['bind'],[['172.20.10.2',0],['192.168.1.93',0]])
            for name,value in original.items():self.assertEqual(selected[name],value)
            before=path.read_bytes()
            for indices in ([16],[25,25],[16,99]):
                with self.assertRaises(ValueError):save_selection(indices,path,links)
                self.assertEqual(path.read_bytes(),before)
            links[0]['up']=False
            with self.assertRaises(ValueError):save_selection([16,25],path,links)
            self.assertEqual(path.read_bytes(),before)

if __name__=='__main__':unittest.main()
