"""Verify global routes cannot activate while any selected physical path is unhealthy."""
import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gamebond import app


class ActivationTests(unittest.TestCase):
    def exercise(self, both_healthy, *, dns=False, dns_failure=False, path_count=2):
        calls = []

        class Node:
            addresses = [(f'192.168.{i+1}.2',1234+i) for i in range(path_count)]

            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                calls.append('start transport')

            def stats(self):
                calls.append('check paths')
                return {'paths': [{'healthy': i<path_count-1 or both_healthy} for i in range(path_count)]}

            def close(self):
                calls.append('close transport')

        class Network:
            def __init__(self, *args, **kwargs):
                pass

            def prepare(self):
                calls.append('prepare endpoint routes')

            def activate(self):
                calls.append('activate global routes')

            def qos_status(self):
                return []

            def close(self):
                calls.append('remove owned routes')

        class Event:
            def is_set(self):
                return False

            def wait(self, timeout):
                return timeout == 5

            def set(self):
                pass

        class Resolver:
            def __init__(self, *args):
                pass
            def start(self):
                calls.append('start DNS responder')
                return self
            def close(self):
                calls.append('close DNS responder')

        class DnsScope:
            def __init__(self, *args):
                pass
            def activate(self):
                calls.append('activate exact DNS rules')
                if dns_failure:
                    raise RuntimeError('DNS policy rejected')
            def status(self):
                return {'active': True}
            def close(self):
                calls.append('remove owned DNS rules')

        class Thread:
            def __init__(self, **kwargs):
                pass

            def start(self):
                calls.append('start packet worker')

            def join(self, *args):
                pass

        tun = SimpleNamespace(name='GameBond', close=lambda: calls.append('close tun'))
        config = {'role': 'client', 'bind': Node.addresses, 'peer': ('203.0.113.1', 4433),
                  'session': '01' * 16, 'client_tunnel_ip': '10.77.0.2'}
        if dns:
            config['dns'] = {'records': {'private.example': {'A': ['127.0.0.1']}}}
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'key'
            key.write_bytes(b'k' * 32)
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(app, 'os', SimpleNamespace(name='nt')))
                stack.enter_context(patch.object(app, 'Node', Node))
                stack.enter_context(patch.object(app, 'open_tun', return_value=tun))
                stack.enter_context(patch.object(app, 'DNSResponder', Resolver))
                stack.enter_context(patch('gamebond.windows_dns.WindowsDnsScope', DnsScope))
                stack.enter_context(patch('gamebond.windows_dns.recover_journals'))
                stack.enter_context(patch('gamebond.windows_network.WindowsNetwork', Network))
                stack.enter_context(patch.object(app.threading, 'Event', Event))
                stack.enter_context(patch.object(app.threading, 'Thread', Thread))
                stack.enter_context(patch.object(app.signal, 'signal', return_value=0))
                stack.enter_context(patch.object(app.time, 'perf_counter', side_effect=[0, 1, 20]))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                if dns_failure:
                    with self.assertRaisesRegex(RuntimeError, 'DNS policy rejected'):
                        app.run(config, key, configure=True)
                elif both_healthy:
                    app.run(config, key, configure=True)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'all selected physical paths'):
                        app.run(config, key, configure=True)
        return calls

    def test_single_healthy_path_never_activates_global_routes(self):
        calls = self.exercise(False)
        self.assertNotIn('activate global routes', calls)
        self.assertIn('remove owned routes', calls)
        self.assertLess(calls.index('remove owned routes'), calls.index('close tun'))

    def test_global_routes_activate_only_after_both_paths_and_workers_ready(self):
        calls = self.exercise(True)
        self.assertLess(calls.index('check paths'), calls.index('activate global routes'))
        self.assertLess(calls.index('start packet worker'), calls.index('activate global routes'))
        self.assertLess(calls.index('activate global routes'), calls.index('remove owned routes'))
        self.assertLess(calls.index('remove owned routes'), calls.index('close tun'))

    def test_dns_listener_precedes_rules_and_cleanup_removes_rules_before_adapter(self):
        calls = self.exercise(True, dns=True)
        self.assertLess(calls.index('check paths'), calls.index('start DNS responder'))
        self.assertLess(calls.index('start DNS responder'), calls.index('activate exact DNS rules'))
        self.assertLess(calls.index('remove owned DNS rules'), calls.index('close DNS responder'))
        self.assertLess(calls.index('close DNS responder'), calls.index('remove owned routes'))

    def test_dns_failure_still_closes_listener_routes_and_adapter(self):
        calls = self.exercise(True, dns=True, dns_failure=True)
        self.assertIn('remove owned DNS rules', calls)
        self.assertIn('close DNS responder', calls)
        self.assertLess(calls.index('remove owned DNS rules'), calls.index('close tun'))
        self.assertIn('remove owned routes', calls)

    def test_dns_rules_never_activate_with_one_healthy_path(self):
        calls = self.exercise(False, dns=True)
        self.assertNotIn('start DNS responder', calls)
        self.assertNotIn('activate exact DNS rules', calls)


    def test_routes_wait_for_every_selected_link_with_three_and_eight_paths(self):
        for count in (3,8):
            with self.subTest(paths=count):
                calls=self.exercise(False,path_count=count)
                self.assertNotIn('activate global routes',calls)
                calls=self.exercise(True,path_count=count)
                self.assertIn('activate global routes',calls)


if __name__ == '__main__':
    unittest.main()
