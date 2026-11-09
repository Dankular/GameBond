from collections import OrderedDict,deque
import io
import json
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import MagicMock,patch

from gamebond.app_events import AppEventStore
from gamebond.app_policy import PolicyEvaluator
from gamebond.policy import parse_packet
from gamebond.userspace import Runtime


class AppAuthorizationTests(unittest.TestCase):
    def test_metrics_larger_than_mtu_do_not_kill_stack_reader(self):
        runtime=object.__new__(Runtime)
        runtime.stop=threading.Event();runtime.app_events=MagicMock();runtime.capture_extension=True
        record=dict(type='app_metrics',applications=[],padding='x'*2000)
        packet=json.dumps(record).encode()
        runtime.stack=MagicMock(stdout=io.BytesIO(struct.pack('!BH',2,len(packet))+packet))
        runtime.app_events.record_usage.side_effect=lambda record:runtime.stop.set()
        runtime.read_stack()
        runtime.app_events.record_usage.assert_called_once_with(record)

    def test_live_policy_reload_returns_explicit_denial_then_allow_without_usage_toast(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json'
            app=r'C:\Apps\browser.exe'
            config=dict(app_rules={app:dict(outbound='block',profile='gaming')})
            path.write_text(json.dumps(config))
            runtime=object.__new__(Runtime);runtime.config=config;runtime.config_path=path
            runtime.policy_lock=threading.Lock();runtime.policy_stamp=None;runtime.application_policy=PolicyEvaluator(config)
            runtime.authorization_slots=threading.BoundedSemaphore(1);runtime.authorization_lock=threading.Lock()
            runtime.authorization_counts=dict(allowed=0,denied=0,errors=0);runtime.authorization_decisions=deque(maxlen=32)
            runtime.app_events=AppEventStore(Path(directory)/'events.json');runtime.write_stack_frame=MagicMock()
            identity=dict(pid=42,created_at=1,created_filetime='134000000000000000',path=app,name='browser.exe')
            request=dict(id='0'*24,pid=42,created_filetime=identity['created_filetime'],protocol='tcp',destination='1.1.1.1:443')
            with patch('gamebond.userspace.resolve_process',return_value=identity):
                runtime.authorization_slots.acquire();runtime.authorize_application(request)
                kind,packet=runtime.write_stack_frame.call_args.args
                self.assertEqual(kind,3);self.assertFalse(json.loads(packet)['allow'])
                self.assertEqual(runtime.authorization_snapshot()['recent'][-1]['reason'],'application_blocked')
                self.assertEqual(runtime.authorization_snapshot()['recent'][-1]['captured_pid'],42)
                self.assertEqual(runtime.authorization_snapshot()['recent'][-1]['captured_created_filetime'],identity['created_filetime'])
                config['app_rules'][app]=dict(outbound='allow',profile='call');path.write_text(json.dumps(config))
                runtime.authorization_slots.acquire();runtime.authorize_application(request)
                response=json.loads(runtime.write_stack_frame.call_args.args[1])
                self.assertTrue(response['allow']);self.assertEqual(response['profile'],'call')
            self.assertEqual(runtime.app_events.snapshot()['events'],[])
            self.assertEqual(runtime.authorization_counts,dict(allowed=1,denied=1,errors=0))

    def test_profile_metadata_uses_exact_packet_flow_key(self):
        runtime=object.__new__(Runtime);runtime.config=dict(client_tunnel_ip='10.77.0.2');runtime.flow_profiles=OrderedDict();runtime.classify_lock=threading.Lock()
        runtime.observe_flow_profile(dict(profile='call',protocol='tcp',source='10.77.0.2:50000',destination='1.1.1.1:443',pid=42,created_filetime='134000000000000000'))
        tcp=struct.pack('!HHIIBBHHH',50000,443,0,0,0x50,0x10,1000,0,0)
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0,0,64,6,0,b'\x0a\x4d\0\x02',b'\x01'*4)
        self.assertEqual(runtime.flow_profiles[parse_packet(ip+tcp).flow]['profile'],'call')
