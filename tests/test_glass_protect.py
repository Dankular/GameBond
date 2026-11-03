import json
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PyQt5.QtWidgets import QApplication

from gamebond.app_policy import save_policy_settings
from gamebond.glass_protect import ProtectPanel


class ProtectPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])

    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.path=Path(self.directory.name)/'client.json'
        self.path.write_text(json.dumps(dict(peer=['195.154.119.136',4433],app_rules={})))
        self.config_patch=patch('gamebond.glass_protect.CONFIG',self.path);self.config_patch.start()
        self.save_patch=patch('gamebond.glass_protect.save_policy_settings',side_effect=lambda **kwargs:save_policy_settings(config_path=self.path,**kwargs));self.save_patch.start()
        self.panel=ProtectPanel();self.panel.resize(1398,840)

    def tearDown(self):
        self.panel.close();self.panel.deleteLater();self.app.processEvents()
        self.save_patch.stop();self.config_patch.stop();self.directory.cleanup()

    def runtime(self,down=1000,up=500,generation=1):
        return dict(pid=10,state='running',app_attribution=dict(available=True),applications=[dict(
            path=r'C:\Apps\Browser.exe',name='Browser',pid=123,created_filetime='123456789012345678',generation=generation,
            downloaded_bytes=down,uploaded_bytes=up,active_connections=1,destinations=['1.1.1.1:443'])])

    def test_table_uses_verified_rows_and_real_counter_deltas(self):
        with patch('gamebond.glass_protect.time.monotonic',side_effect=[10,12,13]):
            self.panel.update_runtime(self.runtime())
            self.panel.update_runtime(self.runtime(down=3000,up=1500))
            self.assertEqual(self.panel.table.item(0,0).text(),'Browser')
            self.assertEqual(self.panel.table.item(0,5).text(),'1.0 KB/s')
            self.assertEqual(self.panel.table.item(0,6).text(),'500 B/s')
            self.assertEqual(self.panel.table.cellWidget(0,1).text(),'Not exposed')
            self.panel.update_runtime(self.runtime(down=4000,up=2000,generation=2))
            self.assertEqual(self.panel.table.item(0,5).text(),'0 B/s')
        self.assertIn('enforcement is unavailable',self.panel.feedback.text())

    def test_outbound_control_persists_rule_and_emits_change_without_claiming_live_enforcement(self):
        self.panel.update_runtime(self.runtime());changes=[];self.panel.settingsChanged.connect(changes.append)
        combo=self.panel.table.cellWidget(0,2);combo.setCurrentIndex(combo.findData('block'))
        config=json.loads(self.path.read_text())
        self.assertEqual(config['app_rules'][r'c:\apps\browser.exe']['outbound'],'block')
        self.assertEqual(len(changes),1);self.assertIn('Reconnect',self.panel.feedback.text())
        self.panel.search.setText('does-not-match')
        self.assertEqual(self.panel.table.rowCount(),0)

    def test_configured_rule_without_activity_is_not_labeled_as_verified_usage(self):
        save_policy_settings(updates={r'C:\Apps\configured.exe':dict(outbound='block',profile='bulk')},config_path=self.path)
        self.panel._load_config();self.panel.update_runtime(None)
        self.assertEqual(self.panel.table.rowCount(),1)
        self.assertIn('no verified tunnel usage',self.panel.table.item(0,0).toolTip())
        self.assertEqual(self.panel.table.item(0,5).text(),'—')
