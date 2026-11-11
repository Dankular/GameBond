"""Write native-edge/appconfig/testdata/vectors.json.gz from the real app.load_config.

Each case is a config dict plus platform options; the expected outcome is only
ok/error (messages differ between languages). Sections validated by their own
Go packages (adaptive_qos, outer_transport, stream_relays, link_policies,
admin, dns) are not mutated here except for their role-dependent gates."""
import copy
import gzip
import json
import random
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond import app  # noqa: E402
sys.path.insert(0, str(ROOT / "tools"))
from _app_config_section_pools import SECTION_POOLS  # noqa: E402

REAL_OS = app.os
G1, G2, G3 = ('{%08X-0000-0000-0000-00000000000%d}' % (0xA0000000 + i, i) for i in (1, 2, 3))
SESSION = '00112233445566778899aabbccddeeff'

CLIENT = {
    'role': 'client', 'bind': [['192.168.1.10', 0], ['10.0.0.5', 0]], 'peer': ['203.0.113.7', 5000],
    'session': SESSION, 'client_tunnel_ip': '10.77.0.2', 'interface_ids': [G1, G2],
    'interface_indices': [11, 12], 'mtu': 1300,
}
SERVER = {'role': 'server', 'bind': [['0.0.0.0', 5000]], 'session': SESSION, 'client_tunnel_ip': '10.77.0.2'}

POOL = {
    'role': ['client', 'server', 'Client', '', None, 3, ['client']],
    'bind': [[], None, [['1.2.3.4', 1]], [['0.0.0.0', 0], ['0.0.0.0', 1]], [['192.168.1.10', 0]],
             [['192.168.1.10', 0], ['192.168.1.10', 1]], [['192.168.1.10', 0], ['10.0.0.5', 70000]],
             [['192.168.1.10', 0], ['10.0.0.5', -1]], [['192.168.1.10', 0], ['10.0.0.5', 1.0]],
             [['192.168.1.10', 0], ['10.0.0.5', True]], [['192.168.1.10', 0], ['010.0.0.5', 1]],
             [['192.168.1.10', 0], ['127.0.0.1', 1]], [['192.168.1.10', 0], ['169.254.1.1', 1]],
             [['192.168.1.10', 0], ['224.0.0.1', 1]], [['192.168.1.10', 0], ['0.0.0.0', 1]],
             [['192.168.1.10', 0], ['10.0.0.5']], [['192.168.1.10', 0], 'ab'], 'ab', 5,
             [['192.168.1.10', 0], [167772165, 0]], [['192.168.1.10', 0], ['10.0.0.5', 0, 9]],
             [['192.168.1.%d' % i, 0] for i in range(1, 10)], [['192.168.1.%d' % i, 0] for i in range(1, 9)]],
    'interface_ids': [None, [], [G1], [G1, G1], [G1, G1.lower()], [G1, ''], ['', ''], [G1, 'x'], [G1, 5],
                      [G1, G2, G3], 'abc', [G1, '{' + 'x' * 36 + '}'], [G1, '{' + 'x' * 37 + '}']],
    'interface_indices': [[], [11], [11, 11], [11, 0], [11, -1], [11, 1 << 24], [11, 12, 13], [11, True], [11, 12.0],
                          [11, (1 << 24) - 1], 'ab', None],
    'peer': [['0.0.0.0', 1], ['224.0.0.1', 1], ['169.254.0.1', 1], ['203.0.113.7', 0], ['203.0.113.7', 65536],
             ['203.0.113.7', '5000'], ['203.0.113.7'], ['203.0.113.7', 9, 9], 'x', None, ['127.0.0.1', 5000],
             [3405803783, 5000]],
    'session': ['', '00', SESSION[:-2], SESSION + '00', SESSION.upper(), ' ' + SESSION, SESSION[:4] + ' ' + SESSION[4:],
                SESSION[:5] + ' ' + SESSION[5:], '\t'.join(SESSION[i:i + 2] for i in range(0, 32, 2)),
                'zz' + SESSION[2:], None, 5, SESSION[:-1], ' ' + SESSION, SESSION + '\x0b', SESSION + '\x1c'],
    'client_tunnel_ip': ['10.77.0.2', '10.77.0.3', 'x', '', None, 5, '10.77.0.2/24', '256.1.1.1', '10.077.0.2'],
    'mtu': [1279, 1280, 1400, 1401, 1300.0, True, None, '1300', 1e3],
    'queues': [{}, {'46': {'priority': True, 'replicate': True}}, {'46': {'priority': True}}, {'64': {}}, {'63': {}},
               {'x': {}}, {'': {}}, {'-1': {}}, {'046': {}}, {'٤٦': {}}, {'²': {}}, {'46': {'capacity': 0}},
               {'46': {'capacity': 1.0}}, {'46': {'capacity': True}}, {'46': {'max_age_ms': 0}},
               {'46': {'max_age_ms': -1}}, {'46': {'max_age_ms': True}}, {'46': {'max_age_ms': False}},
               {'46': {'max_age_ms': '5'}}, {'46': {'retransmissions': 1}}, {'46': {'retransmissions': 0.0}},
               {'46': {'retransmissions': False}}, {'46': {'retransmissions': True}},
               {'46': {'priority': 1}}, {'46': {'replicate': 'yes'}}, {'46': {'bogus': 1}}, {'46': None},
               {'46': []}, None, [], 'x', {'0': {'priority': True}}, {'12345678901234567890': {}}],
    'redundant_mode': [True, False, 0, 1, None, 'true'],
    'bonding_mode': [True, False, 1, None],
    'bonding_initial_rate_mbps': [1, 0, -1, 0.5, 100, 101, True, '1', None, 1e308],
    'bonding_max_rate_mbps': [100, 0, 0.1, 1, 1e308, True, None],
    'reorder_timeout_ms': [30, 0, 0.99, 1, 200, 200.5, True, None, '30'],
    'loss_tracking': [True, False, 1, None],
    'path_mtu_discovery': [True, False, 1],
    'failover_replay': [True, False, 0],
    'repair_deadline_ms': [250, 9, 10, 2000, 2001, True, None],
    'direct_priority': [True, False, 1, None],
    'bulk_rate_mbps': [0, -1, 0.0, 5, 1e308, True, None, '5'],
    'game_udp_ports': [[], [0], [1], [65535], [65536], [27015, 27016], [True], [1.0], ['1'], None, '', 'a', {}, {'1': 1}, 5],
    'lan_tunnel_ips': [[], ['10.77.0.5'], ['10.77.0.5', '10.77.0.5'], ['10.77.0.0'], ['10.77.0.1'], ['10.77.0.2'],
                       ['10.77.0.255'], ['10.78.0.5'], ['x'], 'x', None, ['10.77.0.%d' % i for i in range(3, 36)],
                       ['10.77.0.%d' % i for i in range(3, 35)], [168231941]],
    'lan_devices': [[], None, 'x', [{'name': 'a', 'tunnel_ip': '10.77.0.5', 'interface_id': G3, 'device_mac': '02:00:00:00:00:01'}],
                    [{'name': 'a', 'tunnel_ip': '10.77.0.5', 'interface_id': G1, 'device_mac': '02:00:00:00:00:01'}],
                    [{'name': 'a', 'tunnel_ip': '10.77.0.2', 'interface_id': G3, 'device_mac': '02:00:00:00:00:01'}],
                    [{'name': 'a', 'bogus': 1}], [5]],
    'server_type': ['gamebond', 'omr', 'both', 'x', None],
    'omr': [None, {}, {'server': ['203.0.113.7', 5000]}],
    'admin': [None, {}, {'x': 1}],
    'dns': [None],
}
POOL.update(SECTION_POOLS)


def run_case(cfg, windows, allow):
    app.os = types.SimpleNamespace(name='nt' if windows else 'posix')
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(cfg, f)
        try:
            app.load_config(f.name, allow_unavailable_links=allow)
            return True
        except Exception:
            return False
        finally:
            Path(f.name).unlink()
    finally:
        app.os = REAL_OS


def main():
    rng = random.Random(0x6C0DE)
    cases = []

    def add(cfg, windows, allow):
        cases.append({'config': cfg, 'windows': windows, 'allow': allow, 'ok': run_case(cfg, windows, allow)})

    bases = [CLIENT, SERVER, dict(CLIENT, bonding_mode=True, redundant_mode=False),
             dict(CLIENT, queues={'46': {'priority': True, 'replicate': True}}, game_udp_ports=[27015]),
             dict(SERVER, lan_tunnel_ips=['10.77.0.5']),
             dict(CLIENT, bind=[['0.0.0.0', 0], ['0.0.0.0', 0]]),
             dict(CLIENT, bind=[['192.168.1.10', 0], ['192.168.1.10', 0]]),
             dict(CLIENT, bind=[['192.168.1.10', 0], ['0.0.0.0', 0]])]
    for n in (1, 7, 8, 9):
        bases.append(dict(CLIENT, bind=[['192.168.%d.10' % i, 0] for i in range(n)],
                          interface_ids=['{A0000000-0000-0000-0000-%012d}' % i for i in range(n)],
                          interface_indices=list(range(11, 11 + n))))
    for base in bases:
        for windows in (True, False):
            for allow in (False, True):
                add(copy.deepcopy(base), windows, allow)
                for key, values in POOL.items():
                    for value in values:
                        cfg = copy.deepcopy(base)
                        cfg[key] = copy.deepcopy(value)
                        add(cfg, windows, allow)
                    cfg = copy.deepcopy(base)
                    cfg.pop(key, None)
                    add(cfg, windows, allow)
    for _ in range(3000):
        base = copy.deepcopy(rng.choice(bases))
        for key in rng.sample(sorted(POOL), rng.randint(1, 4)):
            base[key] = copy.deepcopy(rng.choice(POOL[key]))
        add(base, rng.random() < .5, rng.random() < .5)
    ok = sum(c['ok'] for c in cases)
    out = ROOT / 'native-edge' / 'appconfig' / 'testdata' / 'vectors.json.gz'
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, 'wt', encoding='utf-8') as f:
        json.dump(cases, f, separators=(',', ':'))
    print(len(cases), 'cases', ok, 'ok')


if __name__ == '__main__':
    main()
