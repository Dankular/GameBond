import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from PyQt5.QtWidgets import QApplication
from gamebond.glass_dns import DNSPanel,DNSRecordDialog
from gamebond.dns_management import save_profile

def config():
    return dict(role='client',bind=[['192.168.1.93',0],['172.20.10.2',0]],interface_indices=[25,16],session='12'*16,
        peer=['203.0.113.1',4433],client_tunnel_ip='10.77.0.2',capture_mode='all',dns=dict(enabled=True,bind=['10.77.0.2',53],records={'example.net':{'A':['127.0.0.1']}},ttl=15,upstream=None))

class DNSPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])

    def test_save_addresses_ttl_and_upstream_preserves_unrelated_settings_without_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';before=config();path.write_text(json.dumps(before));panel=DNSPanel(config_path=path)
            try:
                panel.ttl.setValue(30);panel.forward.setChecked(True);panel.upstream.setText('1.1.1.1');panel.add_record('example.net','AAAA','::1, 2001:4860::8888')
                with patch('subprocess.Popen') as launch:
                    self.assertTrue(panel.save());launch.assert_not_called()
                saved=json.loads(path.read_text());self.assertEqual(saved['dns']['ttl'],30);self.assertEqual(saved['dns']['upstream'],['1.1.1.1',53]);self.assertEqual(saved['dns']['records']['example.net']['AAAA'],['::1','2001:4860::8888'])
                for key in ('session','peer','capture_mode','bind'):self.assertEqual(saved[key],before[key])
                panel.update_runtime(dict(state='running',backend='userspace'));self.assertIn('Not active',panel.status.text());self.assertIn('not supported',panel.notice.text())
                panel.update_runtime(dict(state='running',dns=dict(queries=10,overrides=4,forwarded=6)));self.assertEqual(panel.status.text(),'Active on this connection');self.assertIn('Queries: 10',panel.metrics.text())
            finally:panel.deleteLater()

    def test_invalid_family_or_duplicate_record_does_not_write_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(config()));before=path.read_bytes();panel=DNSPanel(config_path=path)
            try:
                panel.add_record('wrong.example','A','::1');self.assertFalse(panel.save());self.assertEqual(path.read_bytes(),before)
                panel.records.removeRow(1);panel.add_record('EXAMPLE.NET.','A','1.1.1.1');self.assertFalse(panel.save());self.assertIn('already has',panel.feedback.text());self.assertEqual(path.read_bytes(),before)
            finally:panel.deleteLater()

    def test_dns_conflict_is_rejected_but_unrelated_edit_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';original=config();path.write_text(json.dumps(original));changed=copy.deepcopy(original);changed['capture_mode']='selected';path.write_text(json.dumps(changed))
            saved=save_profile(path,original['dns'],expected=original['dns']);self.assertEqual(saved['capture_mode'],'selected')
            changed=copy.deepcopy(saved);changed['dns']['ttl']=99;path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(RuntimeError,'changed'):save_profile(path,original['dns'],expected=original['dns'])

    def test_toggle_saves_immediately_without_losing_unsaved_advanced_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(config()));panel=DNSPanel(config_path=path)
            try:
                self.assertTrue(panel.advanced.isHidden());panel.ttl.setValue(42)
                with patch('subprocess.Popen') as launch:panel.enabled.click();launch.assert_not_called()
                saved=json.loads(path.read_text());self.assertFalse(saved['dns']['enabled']);self.assertEqual(saved['dns']['ttl'],15)
                self.assertEqual(panel.ttl.value(),42);self.assertTrue(panel.dirty);self.assertTrue(panel.save());self.assertEqual(json.loads(path.read_text())['dns']['ttl'],42)
            finally:panel.deleteLater()

    def test_record_actions_save_and_search_does_not_delete_hidden_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(config()));panel=DNSPanel(config_path=path)
            try:
                self.assertIsNone(panel._commit_record(None,('other.example','A','1.1.1.1')))
                panel.search.setText('other');self.assertEqual(panel.count.text(),'1 of 2 records')
                panel.ttl.setValue(30);self.assertTrue(panel.save());self.assertEqual(len(json.loads(path.read_text())['dns']['records']),2)
                self.assertIn('already exists',panel._commit_record(None,('other.example','A','8.8.8.8')))
                panel.delete_record(1);panel.delete_record(0);saved=json.loads(path.read_text());self.assertFalse(saved['dns']['enabled']);self.assertEqual(saved['dns']['records'],{})
                panel.enabled.click();self.assertFalse(panel.enabled.isChecked());self.assertIn('Add a DNS record',panel.feedback.text())
            finally:panel.deleteLater()

    def test_record_editor_explains_address_family_mismatch(self):
        received=[];dialog=DNSRecordDialog(None,lambda record:received.append(record))
        try:
            dialog.name.setText('example.com');dialog.content.setText('::1');dialog.submit();self.assertEqual(received,[]);self.assertIn('matches',dialog.error.text())
            dialog.family.setCurrentIndex(1);dialog.submit();self.assertEqual(received,[('example.com','AAAA','::1')])
        finally:dialog.deleteLater()
