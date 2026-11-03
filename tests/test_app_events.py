import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,MagicMock

from gamebond.app_events import AppEventStore,resolve_process,FILETIME_UNIX_EPOCH


def activity(pid=42,proof='tcp_connect'):
    return dict(type='app_activity',pid=pid,created_filetime='134000000000000000',
                protocol='tcp' if proof=='tcp_connect' else 'udp',destination='1.1.1.1:443',proof=proof)


class AppEventsTests(unittest.TestCase):
    def test_usage_requires_proven_identity_and_persists_real_counter_deltas(self):
        with tempfile.TemporaryDirectory() as directory:
            owner=dict(pid=42,created_at=1,created_filetime='134000000000000000',path=r'C:\Apps\browser.exe',name='browser.exe')
            path=Path(directory)/'history.json';store=AppEventStore(path,resolver=lambda pid,birth:owner)
            row=dict(pid=42,created_filetime=owner['created_filetime'],generation=1,uploaded_bytes=100,downloaded_bytes=200,
                     active_connections=1,destinations=['1.1.1.1:443'],last_activity=1)
            record=dict(type='app_metrics',applications=[row],skipped_identities=0)
            store.record_usage(record)
            self.assertEqual(store.traffic_snapshot()['rows'],[])
            store.observe(activity());store.record_usage(record);store.record_usage(record)
            self.assertEqual(store.traffic_snapshot()['known_totals'][0]['downloaded_bytes'],200)
            row.update(downloaded_bytes=300,uploaded_bytes=150);store.record_usage(record);store.flush()
            snapshot=store.traffic_snapshot()
            self.assertEqual(snapshot['rows'][0]['uploaded_bytes'],150)
            restored=AppEventStore(path,resolver=lambda pid,birth:owner)
            self.assertEqual(restored.traffic_snapshot()['known_totals'][0]['downloaded_bytes'],300)

    def test_approved_owner_can_exit_before_success_without_pid_reuse_relabelling(self):
        with tempfile.TemporaryDirectory() as directory:
            now=[1.0];store=AppEventStore(Path(directory)/'history.json',resolver=lambda pid,birth:None,clock=lambda:now[0])
            owner=dict(pid=42,created_at=1,created_filetime='134000000000000000',path=r'C:\Apps\short.exe',name='short.exe')
            store.remember_authorized_owner(owner)
            self.assertEqual(store.snapshot()['events'],[])
            self.assertEqual(store.observe(activity())['application']['path'],owner['path'])
            other=activity(43);self.assertIsNone(store.observe(other))

    def test_only_success_proofs_create_events_and_unknown_identity_is_suppressed(self):
        with tempfile.TemporaryDirectory() as directory:
            owner=dict(pid=42,created_at=1,created_filetime='134000000000000000',path=r'C:\Apps\browser.exe',name='browser.exe')
            store=AppEventStore(Path(directory)/'history.json',resolver=lambda pid,birth:owner if pid==42 else None)
            self.assertIsNone(store.observe(dict(activity(),proof='running_process')))
            self.assertIsNone(store.observe(activity(99)))
            event=store.observe(activity())
            self.assertEqual(event['kind'],'new_app_tunnel_use');self.assertEqual(event['application'],owner)
            self.assertEqual(store.snapshot()['rejected_events'],1)
            self.assertEqual(store.snapshot()['unresolved_identities'],1)

    def test_dedup_is_by_canonical_app_path_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'history.json'
            owner=dict(pid=42,created_at=1,created_filetime='134000000000000000',path=r'C:\Apps\browser.exe',name='browser.exe')
            resolve=lambda pid,birth:dict(owner,pid=pid)
            store=AppEventStore(path,resolver=resolve)
            first=store.observe(activity());store.flush()
            owner['path']=r'c:\apps\BROWSER.EXE'
            restored=AppEventStore(path,resolver=resolve)
            self.assertIsNone(restored.observe(activity(43)))
            self.assertEqual(restored.snapshot(after=first['id'])['events'],[])
            self.assertEqual(restored.snapshot(limit=0)['events'],[])

    def test_bounded_event_and_identity_history_and_monotonic_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            resolve=lambda pid,birth:dict(pid=pid,created_at=1,created_filetime=birth,path=fr'C:\Apps\app{pid}.exe',name=f'app{pid}.exe')
            path=Path(directory)/'history.json';store=AppEventStore(path,resolver=resolve,app_limit=2,event_limit=2)
            for pid in (1,2,3):store.observe(activity(pid))
            snapshot=store.snapshot()
            self.assertEqual([e['id'] for e in snapshot['events']],[2,3]);self.assertEqual(snapshot['known_applications'],2)
            store.flush();restored=AppEventStore(path,resolver=resolve,app_limit=2,event_limit=2)
            self.assertEqual(restored.observe(activity(4))['id'],4)

    def test_pid_reuse_does_not_relabel_another_process(self):
        process=MagicMock();process.create_time.return_value=2000
        process.exe.return_value=r'C:\Apps\other.exe';process.name.return_value='other.exe'
        with patch('gamebond.app_events.psutil.Process',return_value=process):
            self.assertIsNone(resolve_process(42,str(FILETIME_UNIX_EPOCH+1000*10_000_000)))
            self.assertEqual(resolve_process(42,str(FILETIME_UNIX_EPOCH+2000*10_000_000))['name'],'other.exe')
