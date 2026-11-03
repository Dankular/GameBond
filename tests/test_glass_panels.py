import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

try:
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt
    from gamebond.glass_panels import HardwarePanel,NetworkScannerPanel
except ImportError:
    QApplication=None

from gamebond.network_scanner import DeviceHistory,normalize_inventory
from gamebond.gpu_monitor import WindowsGPUSampler


def hardware_fixture():
    return dict(observed_at=time.time(),cpu=dict(percent=12,logical_processors=8),
        memory=dict(percent=40,used_bytes=4*1024**3,total_bytes=10*1024**3),
        gpu=dict(percent=18,dedicated_used_bytes=2*1024**3,available=True),
        disk_io={'disk':dict(rates=dict(read_bytes=100000,write_bytes=200000))},
        disks=[dict(mountpoint='C:/',used_bytes=100*1024**3,free_bytes=200*1024**3,percent=33.3)],
        processes=[dict(name='GameBond',pid=123,cpu_percent=1.5,resident_bytes=100000,threads=4,executable='C:/GameBond.exe')],
        adapters=[dict(name='Ethernet',rates=dict(received_bytes=2000,sent_bytes=1000))],errors=[],
        process_coverage=dict(examined=10,returned=1,inaccessible=0),history=[
            dict(monotonic_time=1000+i,cpu_percent=12+i,memory_percent=40,disk_read_bytes_s=100000,disk_write_bytes_s=200000,gpu_percent=18)
            for i in range(3)])


def network_fixture():
    return normalize_inventory(dict(adapters=[dict(index=25,name='Ethernet',address='192.168.1.93',prefix_length=24,up=True)],
        neighbors=[dict(interface_index=25,address='192.168.1.1',mac='aa-bb-cc-dd-ee-ff',state='Stale')]))


class FakeJob:
    def __init__(self,*args):self.state='ready';self.cancelled=False
    def start(self):
        if not self.cancelled:self.state='completed'
        return self
    def cancel(self):self.cancelled=True;self.state='cancelled'
    def snapshot(self):
        return dict(state=self.state,interface_index=25,total=1,completed=1,
                    results=[dict(address='192.168.1.1',responded=True,rtt_ms=3)],errors=[],finished_at=time.time())


@unittest.skipUnless(QApplication is not None,'Optional Qt5 UI dependency')
class GlassPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def wait(self,predicate,seconds=3):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            self.app.processEvents()
            if predicate():return
            time.sleep(.005)
        self.fail('Qt provider result was not delivered')

    def test_hardware_sampling_runs_off_ui_thread_and_populates_graph_footer(self):
        observed=[];main=threading.get_ident()
        class Provider:
            def sample(self):observed.append(threading.get_ident());return hardware_fixture()
            def shutdown(self):pass
        panel=HardwarePanel(sampler=Provider(),autostart=False)
        try:
            panel.refresh();self.wait(lambda:panel.last_snapshot is not None)
            self.assertNotEqual(observed[0],main)
            self.assertEqual(panel.stat_values['cpu'].text(),'12%')
            self.assertEqual(panel.stat_values['gpu'].text(),'18%')
            self.assertEqual(panel.processes_table.rowCount(),1)
            self.assertFalse(panel.details.isVisible())
            self.assertEqual(len(panel.chart.history),3)
        finally:panel.shutdown();panel.close()

    def test_passive_autoload_search_and_explicit_scan_never_scan_on_construction(self):
        factory=Mock(side_effect=FakeJob)
        panel=NetworkScannerPanel(inventory_provider=network_fixture,scan_factory=factory,history=DeviceHistory())
        try:
            self.wait(lambda:panel.last_inventory is not None)
            factory.assert_not_called();self.assertFalse(panel.auto_scan.isChecked())
            self.assertEqual(panel.devices_table.columnCount(),10)
            self.assertEqual(panel.devices_table.rowCount(),1)
            self.assertEqual(panel.devices_table.item(0,0).data(Qt.AccessibleTextRole),'Cached')
            self.assertTrue(panel.devices_table.item(0,9).text())
            panel.search_edit.setText('does not match');self.assertEqual(panel.devices_table.rowCount(),0)
            panel.search_edit.clear();self.assertEqual(panel.devices_table.rowCount(),1)
            panel.scan_button.click();self.wait(lambda:panel.scan_job is not None and panel._reported_finished)
            factory.assert_called_once_with('192.168.1.0/24','192.168.1.93',25)
            self.assertIn('Scanned:',panel.scanned_label.text())
            self.assertEqual(panel.devices_table.item(0,0).data(Qt.AccessibleTextRole),'Reachable')
        finally:panel.shutdown();panel.close()

    def test_shutdown_during_validation_cancels_job_before_start_can_probe(self):
        entered=threading.Event();release=threading.Event();jobs=[]
        def factory(*args):
            entered.set();release.wait(2);job=FakeJob();jobs.append(job);return job
        panel=NetworkScannerPanel(inventory_provider=network_fixture,scan_factory=factory,history=DeviceHistory())
        try:
            self.wait(lambda:panel.last_inventory is not None)
            panel.start_scan();self.assertTrue(entered.wait(1))
            panel.shutdown();release.set()
            self.wait(lambda:bool(jobs))
            self.assertTrue(jobs[0].cancelled)
            self.assertEqual(jobs[0].state,'cancelled')
        finally:release.set();panel.close()


class GPUAndHistoryTests(unittest.TestCase):
    def test_gpu_counter_result_is_real_or_explicitly_unavailable(self):
        runner=Mock(return_value=type('Result',(),dict(returncode=0,stdout=json.dumps(dict(percent=12.5,dedicated_used_bytes=1000,errors=[])).encode()))())
        sampler=WindowsGPUSampler(runner=runner)
        sampler._collect()
        self.assertEqual(sampler.latest['percent'],12.5)
        self.assertEqual(sampler.latest['dedicated_used_bytes'],1000)
        self.assertIsNone(sampler.latest['dedicated_total_bytes'])
        runner.return_value.stdout=json.dumps(dict(percent=None,dedicated_used_bytes=None,errors=['Counters unavailable'])).encode()
        sampler._collect();self.assertFalse(sampler.latest['available']);self.assertIsNone(sampler.latest['percent'])

    def test_device_observation_history_persists_without_claiming_online_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'devices.json';history=DeviceHistory(path)
            device=dict(interface_index=25,address='192.168.1.1',mac='aa:bb:cc:dd:ee:ff',reachable_now=False)
            first=history.observe([device],100)[0];self.assertEqual(first['first_seen'],100)
            restored=DeviceHistory(path);row=restored.observe([device],150)[0]
            self.assertEqual(row['first_seen'],100);self.assertEqual(row['last_seen'],150)
            self.assertFalse(row['reachable_now'])
