import json
from pathlib import Path
import tempfile
import unittest

from gamebond.app_policy import (PolicyEvaluator,authorize,canonical_path,normalize_rules,save_policy_settings)


class ApplicationPolicyTests(unittest.TestCase):
    def test_canonical_rule_blocks_only_the_selected_executable(self):
        config=dict(app_rules={r'C:\Apps\Browser.exe':dict(outbound='block',profile='streaming')})
        policy=PolicyEvaluator(config)
        self.assertEqual(policy.authorize(dict(path='c:/APPS/browser.EXE'),'tcp','1.1.1.1:443'),
                         dict(allow=False,profile='stream',reason='application_blocked'))
        self.assertTrue(policy.authorize(dict(path=r'C:\Other\Browser.exe'),'tcp','1.1.1.1:443')['allow'])
        self.assertTrue(policy.authorize(dict(path=r'C:\Apps\BrowserHelper.exe'),'udp','1.1.1.1:443')['allow'])

    def test_profiles_remain_explicit_and_unknown_identity_fails_closed(self):
        policy=PolicyEvaluator(dict(default_app_profile='gaming'))
        self.assertEqual(policy.authorize(dict(path=r'C:\Game\game.exe'),'udp','195.154.119.136:443')['profile'],'game')
        self.assertFalse(policy.authorize(None,'tcp','1.1.1.1:443')['allow'])
        self.assertFalse(policy.authorize(dict(path='relative.exe'),'tcp','1.1.1.1:443')['allow'])
        self.assertFalse(policy.authorize(dict(path=r'C:\App\a.exe'),'raw','1.1.1.1:443')['allow'])
        self.assertEqual(PolicyEvaluator({}).authorize(dict(path=r'C:\App\a.exe'),'udp','1.1.1.1:443')['profile'],'automatic')

    def test_disabled_protection_bypasses_rule_but_does_not_change_profile(self):
        policy=PolicyEvaluator(dict(protection_enabled=False,app_rules={r'C:\App\app.exe':dict(outbound='block',profile='call')}))
        result=policy.authorize(dict(path=r'C:\App\app.exe'),'tcp','1.1.1.1:443')
        self.assertTrue(result['allow']);self.assertEqual(result['profile'],'call');self.assertEqual(result['reason'],'protection_disabled')
        self.assertTrue(policy.authorize(None,'tcp','1.1.1.1:443')['allow'])

    def test_invalid_configuration_does_not_silently_weaken_rules(self):
        for rules in ({'browser':{}},{r'C:\Apps\a.exe':dict(outbound='anything')},
                      {r'C:\Apps\a.exe':dict(profile=[])},{r'C:\Apps\a.exe':dict(inbound='allow')},
                      {r'C:\Apps\a.exe':dict(outbound='allow'),r'c:/apps/A.EXE':dict(outbound='block')}):
            with self.assertRaises(ValueError):normalize_rules(rules)
        for config in (dict(protection_enabled='false'),dict(default_app_profile=[]),dict(default_app_profile='invented')):
            with self.assertRaises(ValueError):PolicyEvaluator(config)

    def test_save_add_remove_and_toggle_preserve_credentials_and_adapter_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'client.json';original=dict(peer=['195.154.119.136',4433],session='untouched',key_file='secret.key',interface_indices=[25,16])
            path.write_text(json.dumps(original))
            saved=save_policy_settings(updates={r'C:\Apps\browser.exe':dict(outbound='block',profile='bulk')},config_path=path)
            self.assertFalse(authorize(saved,dict(path=r'C:\Apps\BROWSER.exe'),'tcp','1.1.1.1:443')['allow'])
            saved=save_policy_settings(enabled=False,default_profile='streaming',config_path=path)
            for key,value in original.items():self.assertEqual(saved[key],value)
            saved=save_policy_settings(remove_paths=[r'c:/apps/browser.exe'],config_path=path)
            self.assertEqual(saved['app_rules'],{})
            before=path.read_bytes()
            with self.assertRaises(ValueError):save_policy_settings(updates={r'C:\Apps\a.exe':dict(profile='broken')},config_path=path)
            self.assertEqual(path.read_bytes(),before)
