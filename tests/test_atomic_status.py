import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
from gamebond.atomic_io import read_json_shared
from gamebond.userspace import atomic_json,Runtime

class AtomicStatusTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','Windows sharing semantics')
    def test_shared_status_reader_allows_atomic_replacement_while_handle_is_open(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'status.json';atomic_json(path,dict(sequence=0))
            opened=threading.Event();release=threading.Event();results=[];errors=[]
            original=os.fdopen
            def fdopen(fd,mode):
                stream=original(fd,mode);opened.set();release.wait(3);return stream
            def read():
                try:results.append(read_json_shared(path))
                except BaseException as exc:errors.append(exc)
            with patch('gamebond.atomic_io.os.fdopen',side_effect=fdopen):
                reader=threading.Thread(target=read);reader.start()
                try:
                    self.assertTrue(opened.wait(2))
                    atomic_json(path,dict(sequence=1))
                finally:release.set();reader.join(3)
            self.assertEqual(errors,[]);self.assertEqual(results,[dict(sequence=0)])
            self.assertEqual(read_json_shared(path),dict(sequence=1))

    @unittest.skipUnless(os.name=='nt','Windows retry semantics')
    def test_transient_sharing_denial_is_retried_and_temporary_file_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'status.json';atomic_json(path,dict(sequence=0))
            from gamebond.atomic_io import _replace_once
            original=_replace_once;calls=[]
            def replace(source,destination):
                calls.append(1)
                if len(calls)<3:
                    error=PermissionError('reader holds file');error.winerror=32;raise error
                original(source,destination)
            with patch('gamebond.atomic_io._replace_once',side_effect=replace):atomic_json(path,dict(sequence=1))
            self.assertEqual(len(calls),3)
            self.assertEqual(read_json_shared(path),dict(sequence=1))
            self.assertEqual(list(Path(directory).glob('*.tmp-*')),[])

    def test_status_write_failure_during_shutdown_does_not_bypass_resource_cleanup(self):
        runtime=object.__new__(Runtime)
        runtime.config=dict(session='00'*16,bind=[['127.0.0.1',0]],peer=['127.0.0.1',1],interface_indices=[1])
        runtime.key=b'x'*32;runtime.policy_keys=['1'];runtime.stop=threading.Event();runtime.state='starting';runtime.error=None
        runtime.node=runtime.proxy=runtime.stack=None;runtime.adapter_notifications=None
        runtime.publish=Mock(side_effect=[None,PermissionError('locked status'),None]);runtime.worker=Mock();runtime.controller=Mock()
        runtime.refresh_links=Mock();runtime.scheduler=Mock();runtime.authorization_workers=Mock();runtime.job=Mock()
        runtime.workers=[];runtime.logs=[];runtime.listener=Mock();runtime.lan_gateways={}
        with patch('gamebond.transport.Node.start',side_effect=RuntimeError('original startup failure')):
            # Avoid constructing any real sockets, jobs or runtime files.
            with patch('gamebond.userspace.Node') as node,patch('gamebond.windows_adapters.AdapterNotifications'):
                node.return_value.start.side_effect=RuntimeError('original startup failure')
                with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(RuntimeError,'original startup failure'):
                    runtime.run()
        runtime.job.close.assert_called_once();runtime.listener.close.assert_called_once()
        self.assertEqual(runtime.state,'failed')
