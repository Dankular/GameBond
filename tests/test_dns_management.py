import json
from pathlib import Path
import tempfile
import unittest
from gamebond.dns_management import manage


class DNSManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'client.json'
        self.config = dict(role='client', bind=[['192.168.8.2',0],['192.168.9.2',0]],
            interface_indices=[12,18], peer=['203.0.113.10',4433], session='12'*16,
            client_tunnel_ip='10.77.0.2')
        self.path.write_text(json.dumps(self.config))

    def test_edit_exact_mapping_and_disable_without_changing_other_config(self):
        result = manage(self.path, 'set', 'Private.Example.', '127.0.0.1')
        self.assertEqual(result['dns']['records'], {'private.example': {'A': ['127.0.0.1']}})
        self.assertTrue(result['dns']['enabled'])
        self.assertFalse(result['os_settings_changed'])
        self.assertEqual(json.loads(self.path.read_text())['peer'], self.config['peer'])
        self.assertFalse(manage(self.path, 'disable')['dns']['enabled'])
        self.assertTrue(manage(self.path, 'enable')['dns']['enabled'])
        self.assertFalse(manage(self.path, 'remove', 'private.example')['dns']['enabled'])

    def test_invalid_edit_leaves_file_unchanged(self):
        before = self.path.read_bytes()
        for name, address in (('*.example', '127.0.0.1'), ('example.com', 'invalid')):
            with self.subTest(name=name), self.assertRaises(ValueError):
                manage(self.path, 'set', name, address)
            self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(ValueError):
            manage(self.path, 'enable')
        self.assertEqual(self.path.read_bytes(), before)
