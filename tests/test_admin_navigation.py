"""Run deterministic browser-navigation regressions when Node is available."""
from pathlib import Path
import shutil
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(shutil.which('node'),'Node is needed for the portal JavaScript regression tests')
class AdminNavigationTests(unittest.TestCase):
    def test_late_refreshes_cannot_overwrite_other_pages(self):
        result=subprocess.run(['node','--test',str(ROOT/'tests/admin_navigation.test.cjs')],cwd=ROOT,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
if __name__=='__main__':unittest.main()
