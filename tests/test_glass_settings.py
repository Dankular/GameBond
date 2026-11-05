import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from PyQt5.QtWidgets import QApplication,QDialogButtonBox
from gamebond.glass_settings import NetworksDialog
from gamebond.widget_data import save_selection

class NetworkSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])

    def test_missing_phone_is_selectable_and_refresh_preserves_guid_selection(self):
        ids=['{11111111-1111-1111-1111-111111111111}','{22222222-2222-2222-2222-222222222222}']
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(dict(interface_indices=[25,16],interface_ids=ids,interface_names=['Starlink','Phone'])))
            links=[dict(index=25,id=ids[0],name='Starlink',up=True,addresses=['192.168.1.93'],gateway='192.168.1.1')]
            with patch('gamebond.glass_settings.CONFIG',path):dialog=NetworksDialog(links)
            try:
                self.assertEqual(len(dialog.choices),2);phone=dialog.choices[1][1]
                self.assertTrue(phone.isChecked());self.assertTrue(phone.isEnabled());self.assertIn('Offline',phone.text())
                self.assertTrue(dialog.buttons.button(QDialogButtonBox.Save).isEnabled())
                with patch('gamebond.glass_settings.save_selection',side_effect=lambda indices,links:save_selection(indices,path,links)):
                    saved=dialog.write_config()
                self.assertEqual(saved['interface_ids'],ids);self.assertEqual(saved['bind'][1],['0.0.0.0',0])
                dialog._set_links([dict(index=47,id=ids[1],name='Phone',up=True,addresses=['172.20.10.7'],gateway='172.20.10.1'),links[0]])
                self.assertTrue(all(choice.isChecked() for _,choice in dialog.choices))
                with patch('gamebond.glass_settings.save_selection',side_effect=lambda indices,links:save_selection(indices,path,links)):
                    saved=dialog.write_config()
                self.assertEqual(saved['interface_indices'],[25,47]);self.assertEqual(saved['interface_ids'],ids)
            finally:dialog.reject();dialog.deleteLater();self.app.processEvents()


    def test_three_to_eight_adapters_can_be_selected_but_nine_cannot(self):
        from test_multilink import config,links
        c=config(3);inventory=links(config(9))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(c))
            with patch('gamebond.glass_settings.CONFIG',path):dialog=NetworksDialog(inventory)
            try:
                save=dialog.buttons.button(QDialogButtonBox.Save)
                self.assertTrue(save.isEnabled())
                for _,choice in dialog.choices[:8]:choice.setChecked(True)
                self.assertTrue(save.isEnabled())
                self.assertIn('8 adapters selected',dialog.selection_status.text())
                dialog.choices[8][1].setChecked(True);self.assertFalse(save.isEnabled())
                for _,choice in dialog.choices:choice.setChecked(False)
                dialog.choices[0][1].setChecked(True);self.assertFalse(save.isEnabled())
            finally:dialog.reject();dialog.deleteLater();self.app.processEvents()
