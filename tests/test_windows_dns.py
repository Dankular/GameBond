"""DNS scope tests; real PowerShell tests replace all NRPT cmdlets with fakes."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from gamebond.windows_dns import (WindowsDnsScope, WindowsDnsError, _POWERSHELL,
                                  _hostname, cleanup_journal)


class Transcript:
    def __init__(self, fail_activate=False, fail_close=False):
        self.requests = []
        self.fail_activate, self.fail_close = fail_activate, fail_close

    def __call__(self, command, **kwargs):
        request = json.loads(kwargs['input'])
        self.requests.append(request)
        # Planned ownership must already be durable before the worker starts.
        journal = json.loads(Path(request['journal_path']).read_text())
        assert journal['state'] == request['state']
        assert all(rule['marker'] for rule in journal['state']['rules'])
        state = copy.deepcopy(request['state'])
        failed = ((request['phase'] == 'activate' and self.fail_activate) or
                  (request['phase'] == 'close' and self.fail_close))
        for rule in state['rules']:
            rule['verified'] = request['phase'] == 'activate'
            rule['guid'] = '{01234567-89ab-cdef-0123-456789abcdef}'
        return subprocess.CompletedProcess(command, int(failed), json.dumps({
            'ok': not failed, 'state': state, 'error': 'CIM provider refused operation',
            'rollback_errors': ['cleanup refused'] if failed else []}), '')


class WindowsDnsTests(unittest.TestCase):
    def helper(self, **kwargs):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with patch('gamebond.windows_dns._require_windows_admin'), \
                patch('gamebond.windows_dns._process_created', return_value='123'):
            return WindowsDnsScope(['Game.Example.com.'], '10.77.0.2',
                                   journal_dir=directory.name, **kwargs)

    def test_lifecycle_is_idempotent_and_configuration_stays_in_stdin(self):
        helper, transcript = self.helper(), Transcript()
        with patch('gamebond.windows_dns.subprocess.run', side_effect=transcript) as runner:
            helper.activate()
            helper.activate()
            self.assertTrue(helper.status()['active'])
            self.assertEqual(helper.status()['namespaces'], ['game.example.com'])
            helper.close()
            helper.close()
        self.assertEqual([r['phase'] for r in transcript.requests], ['activate', 'close'])
        for call in runner.call_args_list:
            self.assertEqual(call.args[0][-1], _POWERSHELL)
            self.assertNotIn('game.example.com', call.args[0][-1])
            self.assertNotIn('-ExecutionPolicy', call.args[0])
            self.assertFalse(call.kwargs.get('shell', False))
        self.assertFalse(helper._journal_path.exists())
        self.assertFalse(helper.status()['active'])

    def test_partial_activation_and_cleanup_failure_retains_journal_for_retry(self):
        helper, transcript = self.helper(), Transcript(fail_activate=True, fail_close=True)
        with patch('gamebond.windows_dns.subprocess.run', side_effect=transcript):
            with self.assertRaisesRegex(WindowsDnsError, 'cleanup failed'):
                helper.activate()
            self.assertTrue(helper._journal_path.exists())
            transcript.fail_close = False
            helper.close()
        self.assertFalse(helper._journal_path.exists())
        self.assertEqual([r['phase'] for r in transcript.requests], ['activate', 'close', 'close'])

    def test_invalid_transcript_keeps_planned_identity_for_close(self):
        helper = self.helper()
        bad = subprocess.CompletedProcess([], 1, '', 'worker terminated')
        with patch('gamebond.windows_dns.subprocess.run', side_effect=[bad, bad]):
            with self.assertRaisesRegex(WindowsDnsError, 'invalid transcript'):
                helper.activate()
        self.assertTrue(helper._journal_path.exists())
        self.assertIsNone(json.loads(helper._journal_path.read_text())['state']['rules'][0]['guid'])

    def test_namespace_scope_validation(self):
        for name in ('.', '.example.com', '*.example.com', 'example.*', 'singlelabel',
                     'bad..example.com', '-bad.example.com', 'a.example.com..',
                     'example.com;Get-Process', '127.0.0.1', 'a' * 64 + '.com', '\nexample.com'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                _hostname(name)
        with patch('gamebond.windows_dns._require_windows_admin'):
            for names in ([], ['a.example', 'A.example.'], ['a.example'] * 129, 'a.example'):
                with self.assertRaises(ValueError):
                    WindowsDnsScope(names, '10.77.0.2')
            for ip in ('0.0.0.0', '224.0.0.1', '255.255.255.255', '::1'):
                with self.assertRaises(ValueError):
                    WindowsDnsScope(['a.example'], ip)

    def test_recovery_refuses_live_owner_and_live_worker_and_reused_pid_is_safe(self):
        for live_index in (0, 1):
            helper = self.helper()
            helper._save_journal()
            record = json.loads(helper._journal_path.read_text())
            record['worker'] = {'pid': 999, 'created': '456'}
            helper._journal_path.write_text(json.dumps(record))
            with patch('gamebond.windows_dns._require_windows_admin'), \
                    patch('gamebond.windows_dns._record_is_live', side_effect=[live_index == 0, True]), \
                    patch('gamebond.windows_dns.subprocess.run') as runner:
                with self.assertRaisesRegex(WindowsDnsError, 'live process'):
                    cleanup_journal(helper._journal_path)
                runner.assert_not_called()
        with patch('gamebond.windows_dns._require_windows_admin'), \
                patch('gamebond.windows_dns._record_is_live', return_value=False), \
                patch('gamebond.windows_dns._process_created', return_value='new-creation'), \
                patch('gamebond.windows_dns.subprocess.run', side_effect=Transcript()):
            cleanup_journal(helper._journal_path)
        self.assertFalse(helper._journal_path.exists())

    def test_recovery_rejects_broad_or_unowned_journal(self):
        for field, value in (('namespace', '.example.com'), ('marker', 'unowned'), ('guid', 'anything')):
            helper = self.helper()
            helper._save_journal()
            record = json.loads(helper._journal_path.read_text())
            record['state']['rules'][0][field] = value
            helper._journal_path.write_text(json.dumps(record))
            with patch('gamebond.windows_dns._require_windows_admin'), \
                    patch('gamebond.windows_dns.subprocess.run') as runner:
                with self.assertRaises((ValueError, WindowsDnsError)):
                    cleanup_journal(helper._journal_path)
                runner.assert_not_called()


_FAKE_NRPT = r'''
$global:rules = [Collections.Generic.List[object]]::new()
function Get-DnsClientNrptRule { param($Name, $ErrorAction)
    return @($global:rules | Where-Object { -not $Name -or $_.Name -eq $Name })
}
function Get-DnsClientNrptPolicy { param([switch]$Effective, $Namespace, $ErrorAction)
    return @($global:rules | Where-Object { -not $Namespace -or $_.Namespace -eq $Namespace })
}
function Add-DnsClientNrptRule { param($Namespace, $NameServers, $DisplayName, $Comment, [switch]$PassThru, $ErrorAction)
    if ($Namespace -eq 'fail.example.com') { throw 'fake CIM add failure' }
    $rule = [pscustomobject]@{Name='{01234567-89ab-cdef-0123-456789abcdef}'; Namespace=$Namespace;
        NameServers=$NameServers; DisplayName=$DisplayName; Comment=$Comment}
    $global:rules.Add($rule)
    return $rule
}
function Remove-DnsClientNrptRule { param($Name, [switch]$Force, $ErrorAction)
    $match=@($global:rules | Where-Object { $_.Name -eq $Name })
    foreach ($rule in $match) { [void]$global:rules.Remove($rule) }
}
'''


@unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell runtime')
class PowerShellDnsTests(unittest.TestCase):
    def run_ps(self, script, request):
        executable = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) /
                         'System32/WindowsPowerShell/v1.0/powershell.exe')
        return subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', script],
                              input=json.dumps(request), text=True, encoding='utf-8',
                              capture_output=True, timeout=30)

    def test_production_script_parses_without_executing_any_cmdlet(self):
        script = r'''
$text=[Console]::In.ReadToEnd() | ConvertFrom-Json
$tokens=$null; $errors=$null
[void][Management.Automation.Language.Parser]::ParseInput($text.script,[ref]$tokens,[ref]$errors)
@{errors=@($errors | ForEach-Object { $_.Message })} | ConvertTo-Json -Compress
'''
        result = self.run_ps(script, {'script': _POWERSHELL})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['errors'], [])

    def test_actual_powershell_transaction_rolls_back_fake_cim_failure(self):
        # Every NRPT command is shadowed by the fake functions above; this test
        # cannot reach the Windows policy provider. Only temporary journal I/O
        # and .NET/parser code execute for real. Admin check is bypassed here.
        script = _FAKE_NRPT + _POWERSHELL.replace(
            "if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))",
            "if ($false)")
        with tempfile.TemporaryDirectory() as directory:
            request = {'phase': 'activate', 'journal_path': str(Path(directory) / 'state.json'),
                       'owner': {'pid': os.getpid(), 'created': '1'},
                       'state': {'resolver_ip': '10.77.0.2', 'rules': [
                           {'namespace': name, 'marker': f'GameBond-DNS-{"a"*24}-{i}',
                            'guid': None, 'verified': False}
                           for i, name in enumerate(['good.example.com', 'fail.example.com'])]}}
            result = self.run_ps(script, request)
            self.assertEqual(result.returncode, 1, result.stderr or result.stdout)
            data = json.loads(result.stdout)
            self.assertIn('fake CIM add failure', data['error'])
            self.assertEqual(data['rollback_errors'], [])
            self.assertFalse(data['state']['rules'][0]['verified'])
            record = json.loads(Path(request['journal_path']).read_text())
            self.assertGreater(record['worker']['pid'], 0)
            self.assertTrue(record['worker']['created'].isdigit())

    def test_actual_owned_predicate_requires_every_field_but_supports_crash_gap(self):
        script = _POWERSHELL.split('try {\n    $identity', 1)[0] + r'''
$p=$state.rules[0]
$r=[pscustomobject]@{Name='{01234567-89ab-cdef-0123-456789abcdef}';Namespace=$p.namespace;
    NameServers=$state.resolver_ip;DisplayName=$p.marker;Comment=$p.marker}
$results=@(Owned-Rule $r $p)
$p.guid=$r.Name
$results+=Owned-Rule $r $p
foreach ($field in 'Name','Namespace','NameServers','DisplayName','Comment') {
    $old=$r.$field; $r.$field='unowned'; $results+=Owned-Rule $r $p; $r.$field=$old
}
$r.Namespace=@($p.namespace,'another.example.com'); $results+=Owned-Rule $r $p
$r.Namespace=$p.namespace; $r.NameServers='10.77.0.2;8.8.8.8'; $results+=Owned-Rule $r $p
@{results=$results} | ConvertTo-Json -Compress
'''
        result = self.run_ps(script, {'state': {'resolver_ip': '10.77.0.2', 'rules': [{
            'namespace': 'game.example.com', 'marker': 'GameBond-DNS-' + 'a' * 24 + '-0',
            'guid': None, 'verified': False}]}})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['results'], [True, True] + [False] * 7)

    def test_actual_transaction_rejects_existing_namespace_and_effective_override(self):
        modes = {
            'existing': r'''
$global:rules.Add([pscustomobject]@{Name='{11111111-2222-3333-4444-555555555555}';
    Namespace='game.example.com';NameServers='8.8.8.8';DisplayName='administrator';Comment='unowned'})
''',
            'effective': r'''
function Get-DnsClientNrptPolicy { param([switch]$Effective, $Namespace, $ErrorAction)
    foreach ($rule in @($global:rules | Where-Object { $_.Namespace -eq $Namespace })) {
        [pscustomobject]@{Namespace=$rule.Namespace;NameServers='8.8.8.8'}
    }
}
'''}
        for mode, prelude in modes.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                script = _FAKE_NRPT + prelude + _POWERSHELL.replace(
                    "if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))",
                    "if ($false)")
                request = {'phase': 'activate', 'journal_path': str(Path(directory) / 'state.json'),
                           'owner': {'pid': os.getpid(), 'created': '1'},
                           'state': {'resolver_ip': '10.77.0.2', 'rules': [{
                               'namespace': 'game.example.com', 'marker': 'GameBond-DNS-' + 'a'*24 + '-0',
                               'guid': None, 'verified': False}]}}
                result = self.run_ps(script, request)
                self.assertEqual(result.returncode, 1, result.stderr or result.stdout)
                data = json.loads(result.stdout)
                self.assertIn('conflicts' if mode == 'existing' else 'Effective NRPT', data['error'])
                self.assertEqual(data['rollback_errors'], [])
                if mode == 'existing':
                    self.assertIsNone(data['state']['rules'][0]['guid'])


if __name__ == '__main__':
    unittest.main()
