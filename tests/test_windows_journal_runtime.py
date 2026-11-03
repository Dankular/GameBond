"""Run only journal file I/O in the actual Windows PowerShell runtime.

No adapter, route, address or QoS cmdlet is included or executed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from gamebond.windows_network import _POWERSHELL


@unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell integration')
class JournalRuntimeTests(unittest.TestCase):
    def test_repeated_atomic_replace_in_path_with_spaces(self):
        # Extract the production file-writer and its input setup, stopping
        # before the first network function definition.
        script = _POWERSHELL.split('function All-Routes', 1)[0]
        script += '''
Save-State
$state.step = 2
Save-State
$state.step = 3
Save-State
[IO.File]::ReadAllText($request.journal_path)
'''
        with tempfile.TemporaryDirectory(prefix='GameBond journal with spaces ') as directory:
            target = Path(directory) / 'network state.json'
            request = {'journal_path': str(target), 'owner': {'pid': os.getpid()},
                       'state': {'step': 1, 'text': 'caf\u00e9'}}
            executable = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) /
                             'System32/WindowsPowerShell/v1.0/powershell.exe')
            result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', script],
                                    input=json.dumps(request), text=True, encoding='utf-8',
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            record = json.loads(target.read_text(encoding='utf-8'))
            self.assertEqual(record['state'], {'step': 3, 'text': 'caf\u00e9'})
            self.assertEqual(json.loads(result.stdout)['state']['step'], 3)
            self.assertEqual(list(Path(directory).glob('*.tmp-*')), [])


if __name__ == '__main__':
    unittest.main()
