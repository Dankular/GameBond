"""Generate Go compatibility vectors for gamebond.omr_admin.tunnel_settings and normalize_pin."""
import gzip
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.omr_admin import OmrAdminError, normalize_pin, tunnel_settings  # noqa: E402

KEY = ('0123456789abcdefABCDEF' * 3)[:64]
IPS = ['10.255.254.2', 'dhcp', '', None, '0.0.0.0', '224.0.0.1', '127.0.0.1', '169.254.1.1', '8.8.8.8', '1.2.3', 16909060, 0, True, 5.5, [], {}, ['a']]
KEYS = [KEY, KEY + '\n', KEY + '\n\n', ' ' + KEY, KEY[:-1], KEY + '0', 'g' * 64, '', None, 5, ['x'], KEY.lower(), KEY.upper(), '\n' + KEY]
PINS = ['A' * 43 + '=', 'sha256//' + 'A' * 43 + '=', ' sha256//' + 'A' * 43 + '= ', 'A' * 43, 'sha256//sha256//' + 'A' * 43 + '=', 'A' * 42 + '=', 'A' * 44 + '=', '', None, 'A' * 43 + '=\n',
        'a+/' * 14 + 'a=', 'a-' * 21 + 'a=']


def main():
    rng = random.Random(5)
    tunnels = []
    for _ in range(1500):
        g = {}
        if rng.random() < .9:
            g['key'] = rng.choice(KEYS)
        if rng.random() < .8:
            udp = rng.choice([{'client_ip': rng.choice(IPS)}, {}, None, {'host_ip': '1.1.1.1'}, 0, [], 'x', {'client_ip': '10.255.254.2', 'host_ip': 'x'}])
            g['udp'] = udp
        if rng.random() < .7:
            g['chacha'] = rng.choice([True, False, 0, 1, None, '', 'no', [], {}, 0.0, 2])
        g['port'] = rng.choice([1, 'x', None])
        cfg = rng.choice([{'glorytun': g}, {'glorytun': g}, {'glorytun': g}, {}, {'glorytun': None}, {'glorytun': []}, {'glorytun': 'x'}])
        try:
            r = tunnel_settings(cfg)
            res = dict(ok=True, key=r['key'].hex(), tunnel_ip=r['tunnel_ip'], chacha=r['chacha'])
        except OmrAdminError:
            res = dict(ok=False)
        except AttributeError:
            res = dict(ok=False, crash=True)
        tunnels.append(dict(config=cfg, result=res))
    # Deterministic sweep: every address class with a valid key.
    for ip in IPS + ['127.255.255.255', '224.0.0.0', '239.255.255.255', '240.0.0.1', '0.0.0.1', '10.0.0.1', '169.254.9.9', '255.255.255.255', 2130706433, 3758096385]:
        cfg = {'glorytun': {'key': KEY, 'udp': {'client_ip': ip}, 'chacha': 1}}
        r = tunnel_settings(cfg)
        tunnels.append(dict(config=cfg, result=dict(ok=True, key=r['key'].hex(), tunnel_ip=r['tunnel_ip'], chacha=r['chacha'])))
    pins = []
    for p in PINS:
        try:
            pins.append(dict(pin=p, ok=True, out=normalize_pin(p)))
        except (ValueError, TypeError):
            pins.append(dict(pin=p, ok=False))
    dest = ROOT / 'native-edge/omr/testdata/tunnel-vectors.json.gz'
    with gzip.GzipFile(dest, 'wb', mtime=0) as f:
        f.write(json.dumps(dict(tunnels=tunnels, pins=pins), sort_keys=True).encode())
    print(dict(tunnels=len(tunnels), ok=sum(t['result']['ok'] for t in tunnels), crash=sum('crash' in t['result'] for t in tunnels), pins_ok=sum(p['ok'] for p in pins)))


if __name__ == '__main__':
    main()
