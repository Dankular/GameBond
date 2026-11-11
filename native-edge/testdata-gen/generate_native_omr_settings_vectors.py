"""Generate Go compatibility vectors from gamebond.omr_settings.load_server_mode.

Seeded mutations of a valid client config (wrong types, bool/float/int
look-alikes, bad addresses, extra or missing keys) and the accept/reject
decision plus normalized settings Python produces.
"""
import copy
import gzip
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.omr_settings import load_server_mode  # noqa: E402

PIN = 'A' * 43 + '='
JUNK = [None, True, False, 0, 1, -1, 5, 65500, 65536, 70000, 0.5, 100.0, 10000, 10001, 1e400 if False else 1e9, '', ' ', 'x', '10.0.0.1', '1.2.3.4', '01.2.3.4', '127.0.0.1', '0.0.0.0',
        '224.0.0.1', '169.254.1.1', '8.8.8.8', ' 8.8.8.8', '8.8.8.8 ', '1.2.3', '1.2.3.4.5', '256.1.1.1', 16909060, 0, 4294967295, 4294967296, [], [46], [64], [True], [46.0], {}, [1, 2], ['1.2.3.4', 443],
        ['1.2.3.4', 443.0], ['1.2.3.4', True], ['1.2.3.4'], ['1.2.3.4', 1, 2], 'sha256//' + PIN, PIN, 'x' * 600, 'sha256//' + 'B' * 43 + '=', 'A' * 44, ' ' + PIN + ' ']


def base(rng):
    cfg = dict(role='client', server_type='both', omr=dict(server=['203.0.113.7', 65000]))
    omr = cfg['omr']
    if rng.random() < .5:
        omr['key_file'] = 'glorytun.key'
    else:
        omr['admin'] = dict(username='u', password_file='p.txt', pin=PIN)
        if rng.random() < .5:
            omr['admin']['host'] = '203.0.113.9'
        if rng.random() < .5:
            omr['admin']['port'] = 8443
    for key, val in [('tunnel_ip', '10.255.254.9'), ('rate_mbps', rng.choice([1, 2.5, 100.0])), ('beat_ms', 50), ('gamebond_dscp', [46, 10])]:
        if rng.random() < .4:
            omr[key] = val
    return cfg


def paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for k, v in node.items():
            yield from paths(v, prefix + (k,))


def setp(cfg, path, value):
    for k in path[:-1]:
        cfg = cfg[k]
    cfg[path[-1]] = value


def main():
    rng = random.Random(77)
    cases = []
    for i in range(3000):
        cfg = base(rng)
        for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
            op = rng.choice(['set', 'set', 'set', 'del', 'add'])
            ps = [p for p in paths(cfg) if p]
            path = rng.choice(ps)
            if op == 'set':
                setp(cfg, path, copy.deepcopy(rng.choice(JUNK)))
            elif op == 'del':
                node = cfg
                for k in path[:-1]:
                    node = node[k]
                node.pop(path[-1], None)
            else:
                node = cfg
                for k in path:
                    if isinstance(node, dict):
                        node = node[k]
                if isinstance(node, dict):
                    node[rng.choice(['extra', 'key_file', 'admin', 'server', 'tunnel_ip', 'username', 'pin', 'host', 'port'])] = copy.deepcopy(rng.choice(JUNK))
        if rng.random() < .05:
            cfg['server_type'] = rng.choice(['gamebond', 'omr', 'both', 'x', None, 3])
        if rng.random() < .05:
            cfg['role'] = rng.choice(['server', 'client', None])
        if rng.random() < .03:
            cfg.pop('omr', None)
        cases.append(cfg)
    gamebond = [dict(server_type='gamebond'), dict(), dict(role='client'), dict(server_type='gamebond', omr=None), dict(server_type='gamebond', omr={}), dict(server_type='omr', role='client')]
    cases += gamebond
    # Boundary sweep: every numeric/length limit just inside and outside.
    def with_omr(**kw):
        cfg = dict(role='client', server_type='both', omr=dict(server=['203.0.113.7', 65000], key_file='k'))
        cfg['omr'].update(kw)
        return cfg

    def with_admin(**kw):
        admin = dict(username='u', password_file='p', pin=PIN)
        admin.update(kw)
        return dict(role='client', server_type='both', omr=dict(server=['203.0.113.7', 65000], admin=admin))

    for v in [9, 10, 11, 999, 1000, 1001, 10.0]:
        cases.append(with_omr(beat_ms=v))
    for v in [0, 0.09, 0.1, 0.11, 0.2, 9999.9, 10000, 10000.1, 10001, float(1)]:
        cases.append(with_omr(rate_mbps=v))
    for v in [[0], [63], [64], [-1], [0, 63], []]:
        cases.append(with_omr(gamebond_dscp=v))
    for v in [0, 1, 2, 65534, 65535, 65536, 65500.0]:
        cases.append(with_admin(port=v))
        cases.append(with_omr(server=['203.0.113.7', v]))
    for n in [1, 511, 512, 513]:
        for key in ['username', 'password_file']:
            cases.append(with_admin(**{key: 'x' * n}))
    for pin in [PIN, 'sha256//' + PIN, ' sha256//' + PIN + ' ', 'sha256//sha256//' + PIN, 'A' * 42 + '=', 'A' * 43, 'A' * 44 + '=', 'A' * 42 + '+=', 'A' * 43 + '==']:
        cases.append(with_admin(pin=pin))
    for host in ['0.0.0.1', '1.0.0.0', '126.255.255.255', '128.0.0.0', '169.253.255.255', '169.254.0.0', '169.254.255.255', '169.255.0.0', '223.255.255.255', '224.0.0.0', '239.255.255.255', '240.0.0.0', '255.255.255.255']:
        cases.append(with_omr(server=[host, 1], tunnel_ip=host))
        cases.append(with_admin(host=host))
    out = []
    for cfg in cases:
        try:
            mode, s = load_server_mode(cfg)
            res = dict(ok=True, mode=mode, settings=None if s is None else dict(server=list(s.server), key_file=s.key_file, admin=s.admin, tunnel_ip=s.tunnel_ip,
                       tunnel_ip_set=s.tunnel_ip_set, rate_mbps=s.rate_mbps, beat_ms=s.beat_ms, gamebond_dscp=list(s.gamebond_dscp)))
        except (ValueError, TypeError):
            res = dict(ok=False)
        out.append(dict(config=cfg, result=res))
    dest = ROOT / 'native-edge/omr/testdata/settings-vectors.json.gz'
    with gzip.GzipFile(dest, 'wb', mtime=0) as f:
        f.write(json.dumps(out, sort_keys=True).encode())
    print(dict(cases=len(out), accepted=sum(c['result']['ok'] for c in out)))


if __name__ == '__main__':
    main()
