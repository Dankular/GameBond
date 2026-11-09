"""Guard Linux container startup when Git exports from a Windows checkout."""
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('git') and (ROOT/'.git').exists(),'Requires a Git checkout')
class ContainerExportTests(unittest.TestCase):
    def test_windows_git_export_keeps_linux_entrypoint_shebang_lf(self):
        archive=subprocess.check_output(['git','-c',f'safe.directory={ROOT.as_posix()}',
            '-c','core.autocrlf=true','archive','--worktree-attributes','--format=tar','HEAD',
            'tools/container-entrypoint.sh'],cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as contents:
            script=contents.extractfile('tools/container-entrypoint.sh').read()
        self.assertEqual(script.splitlines(keepends=True)[0],b'#!/bin/bash\n',
                         'CRLF makes Linux look for a nonexistent /bin/bash carriage-return interpreter')
        self.assertNotIn(b'\r\n',script)


if __name__=='__main__':unittest.main()
