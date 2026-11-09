import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt5.QtWidgets import QApplication

from gamebond.glass_settings import LanDevicesDialog
from gamebond.widget_data import lan_candidates, save_lan_devices

UPLINKS = ['{11111111-1111-1111-1111-111111111111}', '{22222222-2222-2222-2222-222222222222}']
USB_ID = '{33333333-3333-3333-3333-333333333333}'


def base_config():
    return dict(role='client', client_tunnel_ip='10.77.0.2', interface_indices=[25, 16], interface_ids=UPLINKS,
                interface_names=['Starlink', 'Phone'], bind=[['192.168.1.93', 0], ['0.0.0.0', 0]])


def links():
    return [dict(index=25, id=UPLINKS[0], name='Starlink', description='ethernet', up=True, addresses=['192.168.1.93'], gateway='192.168.1.1'),
            dict(index=16, id=UPLINKS[1], name='Phone', description='tether', up=False, addresses=[], gateway=''),
            dict(index=40, id=USB_ID, name='Ethernet 3', description='USB GbE Family Controller', up=True, addresses=[], gateway=''),
            dict(index=41, id='{44444444-4444-4444-4444-444444444444}', name='Wi-Fi', description='Intel Wi-Fi', up=True, addresses=['192.168.5.4'], gateway='192.168.5.1')]


class LanSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'client.json'
        self.path.write_text(json.dumps(base_config()))

    def test_candidates_exclude_selected_uplinks_and_list_usb_first(self):
        with patch('gamebond.widget_data.usb_adapter_indices', return_value={40}), patch('gamebond.widget_data.os.name', 'nt'):
            rows = lan_candidates(links(), base_config())
        self.assertEqual([r['index'] for r in rows], [40, 41])
        self.assertTrue(rows[0]['usb'] and not rows[1]['usb'])

    def test_save_validates_and_preserves_other_settings(self):
        device = dict(name='PS5', tunnel_ip='10.77.0.3', interface_id=USB_ID, interface_index=40)
        saved = save_lan_devices([device], self.path)
        self.assertEqual(saved['lan_devices'], [device])
        self.assertEqual(json.loads(self.path.read_text())['interface_ids'], UPLINKS)
        before = self.path.read_text()
        for bad in (dict(device, tunnel_ip='10.77.0.2'), dict(device, interface_id=UPLINKS[0]), dict(device, name='')):
            with self.assertRaises(ValueError):
                save_lan_devices([bad], self.path)
        self.assertEqual(self.path.read_text(), before)          # a rejected save never touches the file
        self.assertEqual(save_lan_devices([], self.path)['lan_devices'], [])

    def test_dialog_offers_only_spare_adapters_proposes_an_address_and_saves(self):
        with patch('gamebond.glass_settings.CONFIG', self.path), patch('gamebond.glass_settings.lan_candidates',
                lambda l, c: [dict(r, usb=r['index'] == 40) for r in l if r['index'] in (40, 41)]):
            dialog = LanDevicesDialog(links())
        try:
            self.assertEqual([r['link']['index'] for r in dialog.rows], [40, 41])
            first = dialog.rows[0]
            self.assertEqual(first['ip'].text(), '10.77.0.3')
            self.assertFalse(first['box'].isChecked())
            first['box'].setChecked(True)
            with patch('gamebond.glass_settings.save_lan_devices', side_effect=lambda d: save_lan_devices(d, self.path)):
                config = dialog.write_config()
            self.assertEqual(config['lan_devices'], [dict(name='PS5', tunnel_ip='10.77.0.3', interface_id=USB_ID, interface_index=40)])
        finally:
            dialog.reject()
            dialog.deleteLater()
            self.app.processEvents()

    def test_dialog_reloads_saved_device_and_shows_live_state(self):
        save_lan_devices([dict(name='PS5', tunnel_ip='10.77.0.9', interface_id=USB_ID, interface_index=40)], self.path)
        runtime = dict(lan_devices=[dict(name='PS5', up=True, leased=True)])
        with patch('gamebond.glass_settings.CONFIG', self.path), patch('gamebond.glass_settings.lan_candidates',
                lambda l, c: [dict(r, usb=True) for r in l if r['index'] == 40]):
            dialog = LanDevicesDialog(links(), runtime)
        try:
            row = dialog.rows[0]
            self.assertTrue(row['box'].isChecked())
            self.assertEqual((row['name'].text(), row['ip'].text()), ('PS5', '10.77.0.9'))
            labels = [w.text() for w in dialog.findChildren(type(dialog.status)) if 'addressed' in w.text()]
            self.assertEqual(labels, ['Device connected and addressed'])
        finally:
            dialog.reject()
            dialog.deleteLater()
            self.app.processEvents()


if __name__ == '__main__':
    unittest.main()
