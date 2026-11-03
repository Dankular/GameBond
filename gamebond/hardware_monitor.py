"""Read-only, bounded resource snapshots for the Hardware Resources tab.

Call ``sample`` from a worker, not the UI thread. CPU and I/O rates use this
sampler's own baselines; first samples and counter resets do not invent rates.
"""
from __future__ import annotations

from collections import deque
import threading
import time
import os

import psutil


class HardwareSampler:
    def __init__(self, *, process_limit=100, scan_limit=2048, disk_limit=16,
                 history_limit=360, backend=psutil, clock=time.monotonic, gpu_provider=None):
        if not 1 <= process_limit <= scan_limit <= 8192:
            raise ValueError('Invalid process sample limits')
        if not 1 <= disk_limit <= 64 or not 1 <= history_limit <= 3600:
            raise ValueError('Invalid resource history limits')
        self.backend, self.clock = backend, clock
        self.process_limit, self.scan_limit, self.disk_limit = process_limit, scan_limit, disk_limit
        self.previous_time = None
        self.previous_cpu = None
        self.previous_processes = {}
        self.previous_disks = {}
        self.previous_network = {}
        self.history = deque(maxlen=history_limit)
        self.lock = threading.Lock()
        if gpu_provider is None and os.name=='nt' and backend is psutil:
            from .gpu_monitor import WindowsGPUSampler
            gpu_provider=WindowsGPUSampler()
        self.gpu_provider=gpu_provider

    @staticmethod
    def _delta(current, previous, elapsed):
        if previous is None or elapsed is None or elapsed <= 0:
            return None
        if any(current[key] < previous.get(key, current[key]) for key in current):
            return None
        return {key: (value - previous.get(key, value)) / elapsed for key, value in current.items()}

    def sample(self):
        with self.lock:
            return self._sample()

    def _sample(self):
        backend, now = self.backend, self.clock()
        elapsed = None if self.previous_time is None else now - self.previous_time
        errors = []
        times = backend.cpu_times()._asdict()
        # Linux guest time is already included in user/nice; avoid double count.
        total = sum(value for key, value in times.items() if key not in ('guest', 'guest_nice'))
        idle = times.get('idle', 0) + times.get('iowait', 0)
        cpu = None
        if self.previous_cpu:
            total_delta, idle_delta = total - self.previous_cpu[0], idle - self.previous_cpu[1]
            if total_delta > 0 and 0 <= idle_delta <= total_delta:
                cpu = 100 * (total_delta - idle_delta) / total_delta
        self.previous_cpu = (total, idle)
        logical = backend.cpu_count() or 1
        memory = backend.virtual_memory()
        swap = backend.swap_memory()
        processes = []
        next_processes = {}
        examined = 0
        inaccessible = 0
        attrs = ['pid', 'name', 'exe', 'create_time', 'memory_info', 'cpu_times', 'num_threads']
        for process in backend.process_iter(attrs):
            if examined >= self.scan_limit:
                break
            examined += 1
            try:
                info = process.info
                if info.get('create_time') is None or info.get('cpu_times') is None:
                    inaccessible += 1
                    continue
                key = (info['pid'], info['create_time'])
                process_time = info['cpu_times'].user + info['cpu_times'].system
                old = self.previous_processes.get(key)
                usage = None
                if old is not None and elapsed and elapsed > 0 and process_time >= old:
                    usage = min(100., 100 * (process_time - old) / elapsed / logical)
                next_processes[key] = process_time
                resident = info['memory_info'].rss if info.get('memory_info') is not None else None
                processes.append(dict(pid=info['pid'], create_time=info['create_time'],
                    name=info.get('name') or '', executable=info.get('exe'),
                    cpu_percent=usage, resident_bytes=resident, threads=info.get('num_threads')))
            except (psutil.Error, OSError):
                inaccessible += 1
        self.previous_processes = next_processes
        processes.sort(key=lambda row: (row['cpu_percent'] or 0, row['resident_bytes'] or 0), reverse=True)
        disk_io = {}
        next_disks = {}
        try:
            for name, counter in sorted((backend.disk_io_counters(perdisk=True) or {}).items())[:self.disk_limit]:
                current = dict(read_bytes=counter.read_bytes, write_bytes=counter.write_bytes,
                               read_operations=counter.read_count, write_operations=counter.write_count)
                rates = self._delta(current, self.previous_disks.get(name), elapsed)
                next_disks[name] = current
                disk_io[name] = dict(totals=current, rates=rates)
        except (psutil.Error, OSError) as exc:
            errors.append('Disk counters: ' + str(exc))
        self.previous_disks = next_disks
        disks = []
        try:
            for partition in backend.disk_partitions(all=False)[:self.disk_limit]:
                # Remote drive usage can block on a disconnected file server.
                if 'remote' in partition.opts or partition.mountpoint.startswith('\\\\'):
                    continue
                try:
                    usage = backend.disk_usage(partition.mountpoint)
                    disks.append(dict(device=partition.device, mountpoint=partition.mountpoint,
                                      filesystem=partition.fstype, total_bytes=usage.total,
                                      used_bytes=usage.used, free_bytes=usage.free, percent=usage.percent))
                except (psutil.Error, OSError) as exc:
                    disks.append(dict(device=partition.device, mountpoint=partition.mountpoint, error=str(exc)))
        except (psutil.Error, OSError) as exc:
            errors.append('Disk inventory: ' + str(exc))
        network = []
        next_network = {}
        try:
            statuses = backend.net_if_stats()
            for name, counter in sorted(backend.net_io_counters(pernic=True, nowrap=True).items())[:128]:
                current = dict(received_bytes=counter.bytes_recv, sent_bytes=counter.bytes_sent,
                               received_packets=counter.packets_recv, sent_packets=counter.packets_sent)
                rates = self._delta(current, self.previous_network.get(name), elapsed)
                next_network[name] = current
                status = statuses.get(name)
                network.append(dict(name=name, up=bool(status and status.isup),
                    speed_mbps=status.speed if status else None, totals=current, rates=rates))
        except (psutil.Error, OSError) as exc:
            errors.append('Adapter counters: ' + str(exc))
        self.previous_network = next_network
        self.previous_time = now
        gpu=self.gpu_provider.sample() if self.gpu_provider else dict(percent=None,dedicated_used_bytes=None,available=False,status='unsupported')
        disk_read=sum((row['rates'] or {}).get('read_bytes',0) for row in disk_io.values()) if any(row['rates'] is not None for row in disk_io.values()) else None
        disk_write=sum((row['rates'] or {}).get('write_bytes',0) for row in disk_io.values()) if any(row['rates'] is not None for row in disk_io.values()) else None
        history = dict(monotonic_time=now, cpu_percent=cpu, memory_percent=memory.percent,
                       memory_used_bytes=memory.used,disk_read_bytes_s=disk_read,disk_write_bytes_s=disk_write,
                       gpu_percent=gpu.get('percent'))
        self.history.append(history)
        return dict(observed_at=time.time(), interval_seconds=elapsed, cpu=dict(percent=cpu,
                    logical_processors=logical, normalization='total_machine_capacity'),
            memory=dict(total_bytes=memory.total, available_bytes=memory.available,
                        used_bytes=memory.used, percent=memory.percent),
            swap=dict(total_bytes=swap.total, used_bytes=swap.used, percent=swap.percent),
            disks=disks, disk_io=disk_io,gpu=gpu, adapters=network, processes=processes[:self.process_limit],
            process_coverage=dict(examined=examined, returned=min(len(processes), self.process_limit),
                omitted=max(0, len(processes)-self.process_limit), inaccessible=inaccessible,
                scan_limit=self.scan_limit, scan_limit_reached=examined >= self.scan_limit),
            history=list(self.history), errors=errors,
            limitations=['Process CPU percentages are normalized to total logical CPU capacity.',
                        'First CPU/I/O samples and reset counters have unavailable rates.',
                        'GPU data is unavailable when Windows counters are missing, restricted or unsupported.'])

    def shutdown(self):
        if self.gpu_provider and hasattr(self.gpu_provider,'shutdown'):self.gpu_provider.shutdown()
