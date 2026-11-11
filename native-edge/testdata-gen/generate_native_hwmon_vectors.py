"""Write native-edge/hwmon/testdata/vectors.json.gz from gamebond.hardware_monitor."""
import gzip
import json
import random
import sys
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.hardware_monitor import HardwareSampler  # noqa: E402


class _Tuple:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Times:
    def __init__(self, pairs):
        self.pairs = pairs

    def _asdict(self):
        return dict(self.pairs)


class _Proc:
    def __init__(self, row):
        self.row = row

    @property
    def info(self):
        if self.row.get('err'):
            raise psutil.AccessDenied(1)
        r = self.row
        return {'pid': r['pid'], 'name': r['name'], 'exe': r['exe'], 'create_time': r['create_time'],
                'memory_info': None if r['rss'] is None else _Tuple(rss=r['rss']),
                'cpu_times': None if r['cpu'] is None else _Tuple(user=r['cpu'][0], system=r['cpu'][1]),
                'num_threads': r['threads']}


class FakeBackend:
    Error = psutil.Error

    def __init__(self):
        self.state = None

    def cpu_times(self):
        return _Times([tuple(p) for p in self.state['cpu_times']])

    def cpu_count(self):
        return self.state['cpu_count']

    def virtual_memory(self):
        return _Tuple(**self.state['vm'])

    def swap_memory(self):
        return _Tuple(**self.state['swap'])

    def process_iter(self, attrs):
        return [_Proc(r) for r in self.state['procs']]

    def disk_io_counters(self, perdisk=True):
        d = self.state['disk_io']
        if isinstance(d, str):
            raise OSError(d)
        return {n: _Tuple(read_bytes=a, write_bytes=b, read_count=c, write_count=e) for n, a, b, c, e in d}

    def disk_partitions(self, all=False):
        d = self.state['partitions']
        if isinstance(d, str):
            raise OSError(d)
        return [_Tuple(device=a, mountpoint=b, fstype=c, opts=e) for a, b, c, e in d]

    def disk_usage(self, mount):
        u = self.state['usage'][mount]
        if isinstance(u, str):
            raise OSError(u)
        return _Tuple(total=u[0], used=u[1], free=u[2], percent=u[3])

    def net_if_stats(self):
        d = self.state['if_stats']
        if isinstance(d, str):
            raise OSError(d)
        return {n: _Tuple(isup=v[0], speed=v[1]) for n, v in d.items()}

    def net_io_counters(self, pernic=True, nowrap=True):
        d = self.state['net_io']
        if isinstance(d, str):
            raise OSError(d)
        return {n: _Tuple(bytes_recv=a, bytes_sent=b, packets_recv=c, packets_sent=e) for n, a, b, c, e in d}


class FakeGPU:
    def __init__(self):
        self.value = None

    def sample(self):
        return dict(self.value)


def q(rng, hi):
    return rng.randrange(0, int(hi * 4)) / 4


EXTRA = [f'nic{i:03d}' for i in range(140)]
NAMES = ['eth0', 'Wi-Fi', 'Loopback', 'Ethernet 2', 'vEthernet (WSL)', 'ünï', 'a', 'B']
DISKS = ['PhysicalDrive0', 'PhysicalDrive1', 'sda', 'nvme0n1', 'z', 'A']


def make_state(rng, previous, config):
    st = {}
    cpu_keys = ['user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal', 'guest', 'guest_nice']
    keys = cpu_keys[:rng.choice([4, 4, 7, 10])]
    base = previous.get('cpu_base') or {k: q(rng, 5000) for k in cpu_keys}
    mode = rng.random()
    cur = {}
    for k in keys:
        if mode < 0.05:
            cur[k] = max(0, base[k] - q(rng, 50))  # counter went backwards
        elif mode < 0.12:
            cur[k] = base[k]  # no time passed
        else:
            cur[k] = base[k] + q(rng, 40)
    if 0.12 <= mode < 0.2:
        for k in keys:
            cur[k] = base[k] + (q(rng, 40) + 1 if k == 'idle' else 0)  # all new time is idle: idle_delta == total_delta
    if mode < 0.05 and rng.random() < 0.5:
        cur['idle'] = cur.get('idle', 0) + q(rng, 500)  # idle jumps past total
    previous['cpu_base'] = {**base, **cur}
    st['cpu_times'] = [[k, v] for k, v in cur.items()]
    st['cpu_count'] = rng.choice([None, 0, 1, 4, 8, 16, 64])
    total = rng.randrange(1, 64) * 2 ** 30
    used = rng.randrange(0, total)
    st['vm'] = dict(total=total, available=total - used, used=used, percent=round(used * 100 / total, 1))
    st['swap'] = dict(total=total // 2, used=used // 4, percent=round(used * 25 / total * 2, 1))
    procs = []
    n = rng.choice([0, 1, 5, 30, 150, 400])
    pool = previous['procs']
    for i in range(n):
        pid = rng.randrange(1, 40) if rng.random() < 0.8 else rng.randrange(1, 100000)
        born = pool.get(pid, q(rng, 10 ** 6)) if rng.random() < 0.9 else q(rng, 10 ** 6)
        pool[pid] = born
        t = previous.setdefault('proc_time', {})
        prev_t = t.get((pid, born), q(rng, 500))
        new_t = prev_t + (q(rng, 30) if rng.random() < 0.8 else (-q(rng, 5) if rng.random() < 0.5 else 5000.0))
        t[(pid, born)] = new_t
        row = dict(pid=pid, create_time=born, cpu=[new_t * 0.75, new_t * 0.25], rss=rng.randrange(0, 2 ** 33),
                   name=rng.choice(['python.exe', 'x', '', None, 'ünï.exe']), exe=rng.choice([None, 'C:\\a\\b.exe', '']),
                   threads=rng.choice([None, 1, 12]), err=False)
        roll = rng.random()
        if roll < 0.04:
            row['err'] = True
        elif roll < 0.08:
            row['create_time'] = None
        elif roll < 0.12:
            row['cpu'] = None
        elif roll < 0.16:
            row['rss'] = None
        if rng.random() < 0.15:
            row['cpu'] = row['cpu'] and [row['cpu'][0], row['cpu'][1]]
            row['rss'] = rng.choice([0, 1024, row['rss']])  # ties on resident size
        procs.append(row)
    st['procs'] = procs

    def counters(kind, names, width):
        if rng.random() < 0.05:
            return 'counter failure ' + kind
        out = []
        store = previous[kind]
        for name in rng.sample(names, rng.randrange(0, len(names) + 1)):
            old = store.get(name, [q(rng, 10 ** 6) for _ in range(width)])
            reset = rng.random() < 0.05
            same = rng.random() < 0.15
            new = [v if same else (max(0, v - q(rng, 100)) if reset and i == 0 else v + q(rng, 5000)) for i, v in enumerate(old)]
            new = [int(v) for v in new]
            store[name] = new
            out.append([name, *new])
        return out

    st['disk_io'] = counters('disk', DISKS, 4)
    st['net_io'] = counters('net', NAMES + (EXTRA if rng.random() < 0.3 else []), 4)
    if rng.random() < 0.05:
        st['if_stats'] = 'status failure'
    else:
        st['if_stats'] = {n: [rng.random() < 0.7, rng.choice([0, 100, 1000, 10000])] for n in NAMES + EXTRA if rng.random() < 0.8}
    if rng.random() < 0.05:
        st['partitions'] = 'inventory failure'
        st['usage'] = {}
    else:
        parts, usage = [], {}
        for i in range(rng.choice([0, 1, 3, 20, 70])):
            mount = rng.choice([f'{chr(67 + i % 20)}:\\', f'\\\\server\\share{i}', f'/mnt/d{i}'])
            opts = rng.choice(['rw,fixed', 'rw,remote', 'cdrom', ''])
            parts.append([f'dev{i}', mount, rng.choice(['NTFS', 'ext4', '']), opts])
            usage[mount] = 'denied' if rng.random() < 0.1 else [10 ** 9, 10 ** 8, 9 * 10 ** 8, 10.0]
        st['partitions'], st['usage'] = parts, usage
    return st


def main():
    rng = random.Random(0x4A11)
    scenarios = []
    configs = [dict(), dict(process_limit=1, scan_limit=1), dict(process_limit=5, scan_limit=40, disk_limit=2, history_limit=3),
               dict(process_limit=100, scan_limit=100, disk_limit=1, history_limit=1), dict(scan_limit=8192, history_limit=3600),
               dict(process_limit=50, scan_limit=2048, disk_limit=64, history_limit=360)]
    for index in range(60):
        config = configs[index % len(configs)]
        sampler_backend = FakeBackend()
        gpu = FakeGPU() if index % 3 else None
        sampler = HardwareSampler(backend=sampler_backend, clock=lambda: clock[0], gpu_provider=gpu, **config)
        clock = [rng.choice([0.0, 5.0, 1000.25])]
        previous = {'cpu': [], 'procs': {}, 'disk': {}, 'net': {}}
        steps = []
        for _ in range(rng.randrange(2, 9)):
            state = make_state(rng, previous, config)
            roll = rng.random()
            clock[0] += 0 if roll < 0.05 else (-1.5 if roll < 0.1 else rng.choice([0.25, 1.0, 2.5, 10.0]))
            step = {'state': state, 'clock': clock[0]}
            if gpu is not None:
                gpu.value = rng.choice([
                    dict(percent=None, dedicated_used_bytes=None, available=False, status='not_sampled'),
                    dict(percent=37.5, dedicated_used_bytes=1024, available=True, status='available'),
                    dict(percent=0, available=True),
                    dict(available=False),
                ])
                step['gpu'] = gpu.value
            sampler_backend.state = state
            out = sampler.sample()
            out.pop('observed_at')
            step['expected'] = out
            steps.append(step)
        scenarios.append({'config': config, 'gpu': gpu is not None, 'steps': steps})
    bad = []
    for kwargs in ({'process_limit': 0}, {'process_limit': 10, 'scan_limit': 5}, {'scan_limit': 8193}, {'disk_limit': 0},
                   {'disk_limit': 65}, {'history_limit': 0}, {'history_limit': 3601}, {'process_limit': 8192, 'scan_limit': 8192},
                   {'process_limit': 1, 'scan_limit': 1, 'disk_limit': 64, 'history_limit': 3600}):
        try:
            HardwareSampler(backend=FakeBackend(), **kwargs)
            bad.append({'config': kwargs, 'ok': True})
        except ValueError:
            bad.append({'config': kwargs, 'ok': False})
    out = ROOT / 'native-edge' / 'hwmon' / 'testdata' / 'vectors.json.gz'
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, 'wt', encoding='utf-8', compresslevel=9) as handle:
        json.dump({'scenarios': scenarios, 'limits': bad}, handle, separators=(',', ':'))
    print(out, len(scenarios), sum(len(s['steps']) for s in scenarios))


if __name__ == '__main__':
    main()
