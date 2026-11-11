"""Write native-edge/nrpt/testdata/vectors.json.gz from windows_dns._read_journal,
_hostname and _resolver."""
import copy
import gzip
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond import windows_dns as w  # noqa: E402

TOKEN = '0123456789abcdef01234567'
GUID = '{12345678-1234-1234-1234-123456789abc}'


def rule(i, name=None):
    return {'namespace': name or 'h%d.example.com' % i, 'marker': 'GameBond-DNS-%s-%d' % (TOKEN, i),
            'guid': None, 'verified': False}


def base():
    r1 = rule(1, 'b.example.com')
    r1.update(guid=GUID, verified=True)
    return {'version': 1, 'kind': 'GameBond-DNS', 'owner': {'pid': 100, 'created': '1'}, 'worker': None,
            'state': {'resolver_ip': '10.77.0.2', 'rules': [rule(0, 'a.example.com'), r1]}}


def setter(path, value):
    def apply(record):
        target = record
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return apply


def popper(path):
    def apply(record):
        target = record
        for key in path[:-1]:
            target = target[key]
        target.pop(path[-1])
    return apply


def mutations():
    out = [('base', lambda r: None)]
    for v in (0, 2, True, 1.0, '1', None):
        out.append(('version %r' % (v,), setter(['version'], v)))
    for v in ('x', None, 5):
        out.append(('kind %r' % (v,), setter(['kind'], v)))
    out.append(('no state', popper(['state'])))
    out.append(('state list', setter(['state'], [])))
    for v in ('0.0.0.0', '224.0.0.1', '255.255.255.255', 'x', None, 5, '10.77.0.2', '127.0.0.1'):
        out.append(('resolver %r' % (v,), setter(['state', 'resolver_ip'], v)))
    out.append(('no resolver', popper(['state', 'resolver_ip'])))
    out.append(('rules empty', setter(['state', 'rules'], [])))
    out.append(('rules none', setter(['state', 'rules'], None)))
    out.append(('rules 128', setter(['state', 'rules'], [rule(i) for i in range(128)])))
    out.append(('rules 129', setter(['state', 'rules'], [rule(i) for i in range(129)])))
    for v in ('A.example.com', 'a.example.com.', 'example', '1.2.3.4', 5, None, '*.example.com', 'a_b.example.com', 'b.example.com'):
        out.append(('ns0 %r' % (v,), setter(['state', 'rules', 0, 'namespace'], v)))
    for v in ('GameBond-DNS-%s-1' % TOKEN, 'x', None, 'GameBond-DNS-%s-0 ' % TOKEN):
        out.append(('marker %r' % (v,), setter(['state', 'rules', 0, 'marker'], v)))
    for v in (1, 'true', None):
        out.append(('verified %r' % (v,), setter(['state', 'rules', 0, 'verified'], v)))
    for v in ('x', 5, '12345678-1234-1234-1234-123456789abc', '{12345678-1234-1234-1234-123456789ab}', GUID.upper(),
              '{1234567-1234-1234-1234-123456789abc}', 'x' + GUID):
        out.append(('guid %r' % (v,), setter(['state', 'rules', 0, 'guid'], v)))
    out.append(('no guid key', popper(['state', 'rules', 0, 'guid'])))
    out.append(('no verified key', popper(['state', 'rules', 0, 'verified'])))
    for v in (None, {}, {'pid': 0, 'created': '1'}, {'pid': -1, 'created': '1'}, {'pid': True, 'created': '1'},
              {'pid': 1.0, 'created': '1'}, {'pid': 5, 'created': 5}, {'pid': 5}, [], 'x', {'pid': 5, 'created': '7'}):
        out.append(('owner %r' % (v,), setter(['owner'], v)))
    out.append(('no owner key', popper(['owner'])))
    for v in (None, {'pid': 3, 'created': '9'}, {'pid': 0, 'created': '1'}, 'x', {'pid': 3}):
        out.append(('worker %r' % (v,), setter(['worker'], v)))
    return out


def check(text, token=TOKEN):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / (token + '.json')
        path.write_text(text, encoding='utf-8')
        try:
            w._read_journal(path)
            return True
        except Exception:
            return False


def main():
    journals = []
    for name, fn in mutations():
        record = copy.deepcopy(base())
        fn(record)
        text = json.dumps(record)
        journals.append({'name': name, 'token': TOKEN, 'text': text, 'ok': check(text)})
    for token in ('short', TOKEN.upper(), TOKEN + '0', 'g' * 24):
        text = json.dumps(base())
        journals.append({'name': 'token ' + token, 'token': token, 'text': text, 'ok': check(text, token)})
    for text in ('', '[]', 'null', '{', json.dumps(base()) + ' '):
        journals.append({'name': 'text %r' % text[:10], 'token': TOKEN, 'text': text, 'ok': check(text)})
    big = base()
    big['pad'] = 'x' * (128 * 1024)
    journals.append({'name': 'oversize', 'token': TOKEN, 'text': json.dumps(big), 'ok': check(json.dumps(big))})
    names = []
    for v in ('a.example.com', 'A.EXAMPLE.COM.', 'a', '.', 'a.', '..', 'a..b', 'a-.b', '-a.b', 'a.b-', 'a.1', '1.2.3.4', '1.2.3.4.',
              '0.0.0.0', '::1', 'a.b.c', 'xn--a.com', 'a_b.com', 'é.com', 'a b.com', ('a' * 63) + '.com', ('a' * 64) + '.com',
              '.'.join(['a' * 61] * 4), '.'.join(['a' * 62] * 4), 'a.' * 126 + 'a', 'a.' * 127 + 'a', '*.a.com', 'a.com\n',
              ' a.com', 'a.123', '999.999.999.999', '1.2.3', 'localhost', 'ab', 'a.b', '1.b'):
        try:
            names.append({'in': v, 'ok': True, 'out': w._hostname(v)})
        except Exception:
            names.append({'in': v, 'ok': False})
    resolvers = []
    for v in ('10.77.0.2', '0.0.0.0', '224.0.0.1', '239.255.255.255', '255.255.255.255', '127.0.0.1', '169.254.1.1', 'x', '',
              '1.2.3', '01.2.3.4', '1.2.3.4.5', '::1', '10.77.0.2%1', ' 10.77.0.2', '256.0.0.1'):
        try:
            resolvers.append({'in': v, 'ok': True, 'out': w._resolver(v)})
        except Exception:
            resolvers.append({'in': v, 'ok': False})
    out = ROOT / 'native-edge' / 'nrpt' / 'testdata' / 'vectors.json.gz'
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, 'wt', encoding='utf-8') as f:
        json.dump({'journals': journals, 'hostnames': names, 'resolvers': resolvers}, f, separators=(',', ':'))
    print(len(journals), sum(j['ok'] for j in journals), 'journals ok;', len(names), len(resolvers))


if __name__ == '__main__':
    main()
