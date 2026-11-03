"""A replay ring must never turn a stopped client into a live health report."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('live_status_tool', Path(__file__).parents[1] / 'tools/read-live-status.py')
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveStatusTests(unittest.TestCase):
    def test_no_owner_refuses_replayed_healthy_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'evidence').mkdir()
            self.check_unavailable(root)

    def check_unavailable(self, root):
        with (patch.object(live, 'ROOT', root), patch.object(live, 'read_metadata', return_value={}),
              patch.object(live, 'control', return_value={'state': 'unavailable', 'owner_pid': None}),
              patch.object(live, 'connect') as connect, contextlib.redirect_stdout(io.StringIO()) as output):
            live.main()
        self.assertFalse(json.loads(output.getvalue())['live'])
        connect.assert_not_called()

    def test_running_owner_reads_only_fresh_records_and_rechecks_identity(self):
        transport = dict(paths=[], auth_failures=0, socket_errors=0, receive_drops=0,
                         bonded_packets=1, bonding_deadline_drops=0)
        row = {'transport': transport, 'queues': {'queued': 0}}
        for replacement in (False, True):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'evidence').mkdir()
                sock = Mock()
                sock.recv.return_value = (json.dumps(row) + '\n').encode()
                context = Mock()
                context.__enter__ = Mock(return_value=sock)
                context.__exit__ = Mock(return_value=False)
                states = [{'state': 'running', 'owner_pid': 10},
                          {'state': 'running', 'owner_pid': 11 if replacement else 10}]
                with (patch.object(live, 'ROOT', root), patch.object(live, 'read_metadata', return_value={}),
                      patch.object(live, 'control', side_effect=states),
                      patch.object(live, 'connect', return_value=context) as connect,
                      contextlib.redirect_stdout(io.StringIO()) as output):
                    live.main()
                connect.assert_called_once_with({}, 'attach', tail=0)
                result = json.loads(output.getvalue())
                self.assertEqual(result['live'], not replacement)
                retained = json.loads((root / 'evidence/live-current.json').read_text())
                self.assertEqual(retained['live'], not replacement)
