"""Write native-edge/adminportal/testdata/settings.json.gz from the real AdminSettings,
and system.interfaces/routes reshaping vectors from the real gamebond.admin.system."""
import gzip
import json
import random
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.admin import system  # noqa: E402
from gamebond.admin.server import AdminSettings  # noqa: E402

rng = random.Random(909)
HASH = 'scrypt$32768$c2FsdA==$ZGlnZXN0'
HOSTS = ['127.0.0.1', '0.0.0.0', '10.1.2.3', '127.0.0.2', '8.8.8.8', '01.2.3.4', '1.2.3', '256.1.1.1', 'localhost', '', '::1',
         '1.2.3.4 ', '１.２.３.４', '192.168.1.1']
PORTS = [8443, 1, 65535, 0, 65536, -1, 8443.0, '8443', True, None, 80]
ENABLED = [True, False, 1, 0, None, 'yes']
HASHES = [HASH, '', 'scrypt', 'scrypt$', 'bcrypt$x', None, 5]
PATHS = [None, '', '/tls/admin.crt', 'x']
LOGS = [200, 10, 9, 2000, 2001, 100.0, True, '200', None]

def run_case(raw):
    try:
        s = AdminSettings(raw)
        out = {'ok': {'enabled': s.enabled, 'host': s.bind[0], 'port': s.bind[1], 'password_hash': str(s.password_hash),
                      'tls_cert': s.tls_cert or '', 'tls_key': s.tls_key or '', 'log_lines': s.log_lines}}
    except Exception as exc:  # noqa: BLE001 - the vector records any rejection
        out = {'error': type(exc).__name__}
    return {'raw': raw, 'out': out}


cases = []
for n in range(3000):
    raw = {}
    if n % 2:  # half the cases start from a valid block and mutate one field
        raw = {'enabled': True, 'bind': ['127.0.0.1', 8443], 'password_hash': HASH, 'log_lines': 200}
        if rng.random() < .5:
            raw.update(tls_cert='/c', tls_key='/k')
        key = rng.choice(['enabled', 'bind', 'password_hash', 'tls_cert', 'tls_key', 'log_lines', 'bind'])
        if key == 'bind':
            raw['bind'] = [rng.choice(HOSTS), rng.choice(PORTS)]
        elif key == 'enabled':
            raw['enabled'] = rng.choice(ENABLED)
        elif key == 'password_hash':
            raw['password_hash'] = rng.choice(HASHES)
        elif key == 'log_lines':
            raw['log_lines'] = rng.choice(LOGS)
        else:
            raw[key] = rng.choice(PATHS)
        cases.append(run_case(raw))
        continue
    if rng.random() < .8:
        raw['enabled'] = rng.choice(ENABLED)
    if rng.random() < .85:
        raw['bind'] = rng.choice([[rng.choice(HOSTS), rng.choice(PORTS)], [rng.choice(HOSTS)], 'x', None, [], [1, 2, 3]])
    if rng.random() < .85:
        raw['password_hash'] = rng.choice(HASHES)
    for key in ('tls_cert', 'tls_key'):
        if rng.random() < .5:
            raw[key] = rng.choice(PATHS)
    if rng.random() < .5:
        raw['log_lines'] = rng.choice(LOGS)
    if rng.random() < .05:
        raw['extra'] = 1
    if rng.random() < .02:
        raw = rng.choice([[], 'x', None, 5])
    cases.append(run_case(raw))


IP_ADDR = [{'ifname': 'eth0', 'operstate': 'UP', 'mtu': 1500, 'address': 'aa:bb', 'addr_info': [{'local': '10.0.0.2', 'prefixlen': 24},
           {'local': 'fe80::1', 'prefixlen': 64}, {}], 'stats64': {'rx': {'bytes': 5}, 'tx': {'bytes': 6}}},
           {'ifname': 'lo'}, {'ifname': 'x', 'stats64': {}}, {'ifname': 'y', 'stats64': None}]
ROUTES = [{'dst': 'default', 'gateway': '10.0.0.1', 'dev': 'eth0', 'protocol': 'dhcp', 'prefsrc': '10.0.0.2'}, {'dst': '10.0.0.0/24'}, {}]
shapes = []
for name, fn, data in (('interfaces', system.interfaces, IP_ADDR), ('routes', system.routes, ROUTES), ('interfaces', system.interfaces, []),
                       ('routes', system.routes, [])):
    with mock.patch.object(system, '_run', return_value=(json.dumps(data), None)):
        shapes.append({'kind': name, 'input': data, 'out': fn()})
with mock.patch.object(system, '_run', return_value=('', None)):
    shapes.append({'kind': 'routes', 'input': None, 'empty_output': True, 'out': system.routes()})
dest = ROOT / 'native-edge/adminportal/testdata'
dest.mkdir(parents=True, exist_ok=True)
with gzip.open(dest / 'vectors.json.gz', 'wt', encoding='utf-8') as f:
    json.dump({'settings': cases, 'shapes': shapes}, f, ensure_ascii=False)
print(sum(1 for c in cases if 'ok' in c['out']), len(cases), len(shapes))
