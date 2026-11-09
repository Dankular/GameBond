"""Write native-edge/adminauth/testdata/vectors.json.gz from gamebond.admin.auth."""
import base64
import gzip
import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.admin import auth  # noqa: E402


def b64(data):
    return base64.b64encode(data).decode()


def main():
    rng = random.Random(0xAD31)
    passwords = ['correct horse battery', 'pässwörd-ünïcode-1', '0123456789', 'a' * 200, 'tab\tand space ok!!', 'emoji-\U0001f600-pass']
    verify = []
    for password in passwords:
        for n in (2, 16, 1024, 2 ** 15):
            stored = auth.hash_password(password, n=n)
            verify.append({'password': password, 'stored': stored, 'ok': auth.verify_password(password, stored)})
            verify.append({'password': password + 'x', 'stored': stored, 'ok': auth.verify_password(password + 'x', stored)})
            scheme, nn, salt, digest = stored.split('$')
            variants = [
                '$'.join(('scrypt', nn, salt, digest)) + '$extra', '$'.join(('scrypt', nn, salt)), '$'.join(('bcrypt', nn, salt, digest)),
                '$'.join(('scrypt', '0', salt, digest)), '$'.join(('scrypt', '3', salt, digest)), '$'.join(('scrypt', 'x', salt, digest)),
                '$'.join(('scrypt', nn, '!!!', digest)), '$'.join(('scrypt', nn, salt, '!!!')), '$'.join(('scrypt', nn, salt, '')),
                '$'.join(('scrypt', nn, '', digest)), '$'.join(('scrypt', ' ' + nn, salt, digest)), '$'.join(('scrypt', nn, salt, digest[:-4])),
                '$'.join(('scrypt', '+' + nn, salt, digest)), '$'.join(('scrypt', nn, salt + '\n', digest)), '', 'scrypt', '$$$',
            ]
            for variant in variants:
                try:
                    ok = auth.verify_password(password, variant)
                except Exception as exc:  # must not escape in Python either
                    ok = 'raise:' + type(exc).__name__
                verify.append({'password': password, 'stored': variant, 'ok': ok})
    for n in (2 ** 16, 2 ** 17):
        salt = bytes(range(16))
        digest = hashlib.scrypt(b'memory-limit-pass', salt=salt, n=n, r=8, p=1, maxmem=1024 * 1024 * 1024, dklen=32)
        stored = 'scrypt$%d$%s$%s' % (n, b64(salt), b64(digest))
        verify.append({'password': 'memory-limit-pass', 'stored': stored, 'ok': auth.verify_password('memory-limit-pass', stored)})
    for length in (0, 1, 9, 10, 11):
        try:
            auth.hash_password('x' * length, n=2)
            verify.append({'hash_len': length, 'ok': True})
        except ValueError:
            verify.append({'hash_len': length, 'ok': False})
    # deterministic digest known-answer: fixed salt
    salt = bytes(range(16))
    kat = []
    for password in passwords[:3]:
        digest = hashlib.scrypt(password.encode(), salt=salt, n=1024, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)
        kat.append({'password': password, 'stored': 'scrypt$1024$%s$%s' % (b64(salt), b64(digest))})

    throttle_runs = []
    for run in range(40):
        clock = [0.0]
        kwargs = {}
        if run % 3 == 1:
            kwargs = dict(free=1, base=1.5, cap=20.0, global_limit=5, window=30.0)
        if run % 3 == 2:
            kwargs = dict(free=2, base=2.0, cap=900.0, global_limit=4096, window=300.0)
        throttle = auth.Throttle(clock=lambda: clock[0], **kwargs)
        steps = []
        for _ in range(rng.randint(10, 60)):
            op = rng.choice(['fail', 'fail', 'fail', 'success', 'wait', 'wait'])
            addr = rng.choice(['a', 'b', 'c', '1.2.3.4'])
            if op == 'wait':
                delta = rng.choice([0.5, 1, 3, 10, 60, 301, 1000])
                clock[0] += delta
                steps.append({'op': 'wait', 'dt': delta})
            elif op == 'fail':
                throttle.fail(addr)
                steps.append({'op': 'fail', 'addr': addr})
            else:
                throttle.success(addr)
                steps.append({'op': 'success', 'addr': addr})
            steps.append({'op': 'retry', 'addr': addr, 'want': throttle.retry_after(addr)})
        throttle_runs.append({'kwargs': kwargs, 'steps': steps})
    # eviction: more than 4096 distinct addresses clears all failure state
    clock = [0.0]
    throttle = auth.Throttle(clock=lambda: clock[0], free=0, global_limit=10 ** 9)
    evict = {'steps': [], 'count': 4098}
    for i in range(4098):
        throttle.fail('h%d' % i)
    evict['want_first'] = throttle.retry_after('h0')
    evict['want_last'] = throttle.retry_after('h4097')
    out = ROOT / 'native-edge' / 'adminauth' / 'testdata' / 'vectors.json.gz'
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, 'wt', encoding='utf-8') as f:
        json.dump({'verify': verify, 'kat': kat, 'throttle': throttle_runs, 'evict': evict}, f, separators=(',', ':'))
    print(len(verify), 'verify', sum(1 for v in verify if v.get('ok') is True), 'ok;', len(throttle_runs), 'throttle runs')


if __name__ == '__main__':
    main()
