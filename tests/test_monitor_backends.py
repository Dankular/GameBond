from collections import namedtuple
import ctypes
import os
import socket
import struct
import threading
import time
import unittest
from types import SimpleNamespace as Row
from unittest.mock import Mock, patch

from gamebond.hardware_monitor import HardwareSampler
from gamebond.network_scanner import DiscoveryJob, normalize_inventory, validate_scan, icmp_probe


CPU = namedtuple('CPU', 'user system idle')


class FakeHardware:
    def __init__(self):
        self.cpu = CPU(10, 10, 80)
        self.process = Row(pid=10, name='app', exe='C:/app.exe', create_time=1,
                          memory_info=Row(rss=1000), cpu_times=Row(user=1, system=1), num_threads=3)
        self.io = 1000
    def cpu_times(self): return self.cpu
    def cpu_count(self): return 4
    def virtual_memory(self): return Row(total=10000, available=6000, used=4000, percent=40)
    def swap_memory(self): return Row(total=2000, used=100, percent=5)
    def process_iter(self, attrs): return [Row(info=vars(self.process))]
    def disk_io_counters(self, perdisk):
        return {'disk': Row(read_bytes=self.io, write_bytes=self.io, read_count=10, write_count=20)}
    def disk_partitions(self, all): return [Row(device='C:', mountpoint='C:/', fstype='NTFS', opts='rw,fixed')]
    def disk_usage(self, mount): return Row(total=20000, used=5000, free=15000, percent=25)
    def net_if_stats(self): return {'ethernet': Row(isup=True, speed=1000)}
    def net_io_counters(self, pernic, nowrap):
        return {'ethernet': Row(bytes_recv=self.io, bytes_sent=self.io, packets_recv=100, packets_sent=50)}


ADAPTERS = [dict(index=25, address='192.168.1.93', subnet='192.168.1.0/24', up=True)]


class HardwareMonitorTests(unittest.TestCase):
    def test_real_deltas_are_separate_from_totals_and_first_sample_is_unknown(self):
        backend = FakeHardware(); now = [10]
        sampler = HardwareSampler(backend=backend, clock=lambda: now[0])
        first = sampler.sample()
        self.assertIsNone(first['cpu']['percent'])
        self.assertIsNone(first['processes'][0]['cpu_percent'])
        self.assertIsNone(first['adapters'][0]['rates'])
        backend.cpu = CPU(12, 12, 86); backend.io = 3000
        backend.process.cpu_times = Row(user=2, system=2); now[0] = 12
        second = sampler.sample()
        self.assertEqual(second['cpu']['percent'], 40)
        self.assertEqual(second['processes'][0]['cpu_percent'], 25)
        self.assertEqual(second['disk_io']['disk']['rates']['read_bytes'], 1000)
        self.assertEqual(second['adapters'][0]['rates']['received_bytes'], 1000)

    def test_pid_reuse_and_counter_resets_do_not_report_invented_activity(self):
        backend=FakeHardware(); now=[1]
        sampler=HardwareSampler(backend=backend,clock=lambda:now[0])
        sampler.sample();now[0]=2;backend.process.create_time=5;backend.io=0
        current=sampler.sample()
        self.assertIsNone(current['processes'][0]['cpu_percent'])
        self.assertIsNone(current['adapters'][0]['rates'])
        self.assertIsNone(current['disk_io']['disk']['rates'])

    def test_process_output_and_history_are_bounded(self):
        backend=FakeHardware(); now=[0]
        backend.process_iter=lambda attrs: [Row(info={**vars(backend.process),'pid':i}) for i in range(30)]
        sampler=HardwareSampler(process_limit=2,scan_limit=5,history_limit=2,backend=backend,clock=lambda:now[0])
        for _ in range(4):now[0]+=1;sample=sampler.sample()
        self.assertEqual(len(sample['processes']),2)
        self.assertEqual(sample['process_coverage']['examined'],5)
        self.assertEqual(len(sample['history']),2)


class ScannerTests(unittest.TestCase):
    def test_passive_cache_preserves_staleness_and_removes_broadcast_entries(self):
        record=dict(adapters=[dict(index=25,name='Ethernet',address='192.168.1.93',prefix_length=24,up=True)],
                    neighbors=[dict(interface_index=25,address='192.168.1.1',mac='aa-bb-cc-dd-ee-ff',state='Stale'),
                               dict(interface_index=25,address='224.0.0.1',mac='ff-ff-ff-ff-ff-ff',state='Permanent')])
        result=normalize_inventory(record)
        self.assertEqual(len(result['devices']),1)
        self.assertFalse(result['devices'][0]['reachable_now'])
        self.assertEqual(result['devices'][0]['source'],'neighbor_cache')
        self.assertFalse(result['active_probe'])

    def test_discovery_rejects_nonlocal_public_oversized_and_inactive_subnets(self):
        for network,source,index in [('8.8.8.0/24','192.168.1.93',25),
                                     ('192.168.0.0/16','192.168.1.93',25),
                                     ('192.168.2.0/24','192.168.1.93',25),
                                     ('192.168.1.0/24','192.168.1.93',99)]:
            with self.assertRaises(ValueError):validate_scan(network,source,index,ADAPTERS)
        source,targets=validate_scan('192.168.1.0/24','192.168.1.93',25,ADAPTERS)
        self.assertEqual(source,'192.168.1.93');self.assertNotIn(source,targets)
        self.assertEqual(len(targets),253)

    def test_constructing_job_never_sends_probes_and_execution_reports_actual_results(self):
        probe=Mock(side_effect=lambda source,target,timeout:dict(address=target,responded=target.endswith('.1'),status=0,rtt_ms=2))
        adapters=[dict(index=1,address='192.168.1.2',subnet='192.168.1.0/29',up=True)]
        job=DiscoveryJob('192.168.1.0/29','192.168.1.2',1,adapters=adapters,probe=probe)
        probe.assert_not_called();job.start();job.thread.join(2)
        result=job.snapshot()
        self.assertEqual(result['state'],'completed');self.assertEqual(result['completed'],5)
        self.assertEqual(sum(row['responded'] for row in result['results']),1)
        self.assertEqual(probe.call_count,5)

    def test_cancellation_does_not_submit_remaining_hosts(self):
        started=threading.Event();release=threading.Event();calls=[]
        def probe(source,target,timeout):
            calls.append(target);started.set();release.wait(1)
            return dict(address=target,responded=False,status=11010,rtt_ms=None)
        job=DiscoveryJob('192.168.1.0/24','192.168.1.93',25,adapters=ADAPTERS,probe=probe,workers=1)
        job.start();self.assertTrue(started.wait(1));job.cancel();release.set();job.thread.join(2)
        self.assertEqual(job.snapshot()['state'],'cancelled');self.assertEqual(len(calls),1)

    @unittest.skipUnless(os.name=='nt','Windows ICMP signature without sending traffic')
    def test_source_bound_native_probe_decodes_reply_and_always_closes_handle(self):
        api=Mock();api.IcmpCreateFile.return_value=123
        def reply(*args):
            self.assertEqual(args[4],struct.unpack('=I',socket.inet_aton('192.168.1.93'))[0])
            packet=struct.pack('<III',struct.unpack('=I',socket.inet_aton('192.168.1.1'))[0],0,7)
            ctypes.memmove(args[9],packet,len(packet));return 1
        api.IcmpSendEcho2Ex.side_effect=reply
        with patch('ctypes.WinDLL',return_value=api):result=icmp_probe('192.168.1.93','192.168.1.1')
        self.assertTrue(result['responded']);self.assertEqual(result['rtt_ms'],7)
        api.IcmpCloseHandle.assert_called_once_with(123)
