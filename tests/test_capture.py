import json
from pathlib import Path
import tempfile
import unittest

from gamebond.capture import normalize_apps, proxy_configuration
from gamebond.widget_data import save_applications


class CaptureSettingsTests(unittest.TestCase):
    def test_all_is_default_and_excludes_the_tunnel_carriers(self):
        root=Path('D:/GameBond')
        config=proxy_configuration({},'127.0.0.1:1234',root,executable='C:/Python/pythonw.exe')
        self.assertEqual(config['proxies'][0]['appNames'],[''])
        for path in ('C:/Python/pythonw.exe','C:/Python/python.exe',str(root/'build/gamebond-netstack.exe'),
                     str(root/'.runtime/userspace-proxy/ProxiFyre.exe')):
            self.assertIn(str(Path(path)),config['excludes'])
        self.assertNotIn(str(root/'build/gamebond-internet-probe.exe'),config['excludes'])

    def test_selected_apps_never_create_an_accidental_catch_all(self):
        root=Path('D:/GameBond')
        for apps in ([],['C:/Apps/browser.exe']):
            config=proxy_configuration(dict(capture_mode='selected',cod_executables=apps),'127.0.0.1:1234',root)
            rules=config['proxies'][0]['appNames']
            self.assertNotIn('',rules)
            self.assertIn(str(root/'build/gamebond-internet-probe.exe'),rules)
        for invalid in ('', 'chrome', 'relative/app.exe', 'C:/Apps/config.json'):
            with self.assertRaises(ValueError):normalize_apps([invalid])
        self.assertEqual(len(normalize_apps(['C:/Apps/Test.exe',r'c:\apps\TEST.EXE'])),1)

    def test_save_add_remove_and_switch_mode_preserve_network_and_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json'
            original=dict(peer=['195.154.119.136',4433],session='keep',key_file='secret.key',interface_indices=[25,16])
            path.write_text(json.dumps(original))
            saved=save_applications('selected',['C:/Apps/browser.exe'],path)
            self.assertEqual(saved['capture_mode'],'selected')
            self.assertEqual(saved['cod_executables'],[r'C:\Apps\browser.exe'])
            saved=save_applications('all',[],path)
            self.assertEqual(saved['cod_executables'],[])
            for key,value in original.items():self.assertEqual(saved[key],value)
            before=path.read_bytes()
            with self.assertRaises(ValueError):save_applications('bad',[],path)
            self.assertEqual(path.read_bytes(),before)
