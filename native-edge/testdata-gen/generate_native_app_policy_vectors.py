"""Vectors for native-edge/apppolicy from the real gamebond.app_policy.

    python tools/generate_native_app_policy_vectors.py

Writes native-edge/apppolicy/testdata/vectors.json.gz: canonical_path results
for a generated path corpus, and PolicyEvaluator results (snapshot, digest and
authorize decisions) for generated configurations. Lone surrogates are not
generated: JSON decoders disagree about them.
"""
import gzip
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond import app_policy  # noqa: E402

rng = random.Random(0xA991)
B = '\\'
PREFIXES = ['C:' + B, 'c:/', 'C:', 'z:' + B, B * 2 + 'server' + B + 'share' + B, '//srv/sh/', B * 2 + '?' + B + 'C:' + B,
            B * 2 + '?' + B + 'UNC' + B + 'srv' + B + 'share' + B, B * 2 + '?' + B + 'unc' + B + 'srv' + B + 'share' + B,
            B * 2 + '.' + B + 'dev' + B, B, '/', '', ' ', '\t C:' + B, 'C:' + B + ' ', '1:' + B, ':' + B, 'C:' + B * 2, B * 2 + 'srv',
            B * 2 + 'srv' + B, B * 2 + 'srv' + B + 'sh', '\u00a0C:' + B, '\x1fC:' + B, '\u3000C:' + B, 'C:/Program Files/', 'D:' + B + 'Games' + B,
            'C:' + B + 'Windows' + B + '..' + B, 'C:' + B + '..' + B, 'C:' + B + '.' + B]
MIDDLES = ['App', 'a' + B + '..' + B + 'b', '.' + B + 'x', 'a//b', '..' + B + '..' + B + 'x', 'a' + B + '.', 'ECOLE', '\u00c9COLE', '\u0130',
           '\u03a3A\u03a3', '\u01c5', 'a' + B * 2 + 'b', 'A B', 'x' + B + 'y' + B + 'z', '..', '.', '', 'a' + B + '..', 'a' + B + '..' + B + '..',
           'Z\u212a', '\u1e9e', '\u2160', 'q\U0001d400', 'a/./b/../c', 'MixedCASE', '\u0391\u0392', 'app\x00', 'app\u2028x']
SUFFIXES = ['.exe', '.EXE', '.ExE', '.exe ', ' .exe', '.exe\t', '.exe\x1f', '\u00a0.exe', '.com', '.exe.', '.exe' + B, '', '.exe\u3000', '.ex\u0435',
            '.\u0435xe', 'exe', '.EXE\n', B + '.exe', '/.exe', '.exe/']
paths = []
for prefix in PREFIXES:
    for middle in MIDDLES:
        for suffix in SUFFIXES:
            if rng.random() < .09:
                paths.append(prefix + middle + suffix)
paths += ['', ' ', B, 'C:' + B + 'x.exe', 'c:/X.EXE', 'C:' + B + 'a' + B + 'b.exe', 'C:' + B + 'a' + B + '..' + B + '..' + B + 'b.exe',
          'C:' + B + 'a' * 32760 + '.exe', 'C:' + B + 'a' * 32764 + '.exe', 'x' * 32768, 'x' * 32769, B * 2 + 'srv' + B + 'share' + B + 'app.exe',
          B * 2 + '?' + B + 'C:' + B + 'app.exe', B * 2 + '?' + B + 'UNC' + B + 's' + B + 'sh' + B + 'app.exe', B * 2 + '?' + B + 'UNC' + B + 's' + B + 'app.exe']
paths = list(dict.fromkeys(paths))
path_cases = []
for path in paths:
    try:
        path_cases.append(dict(path=path, ok=True, out=app_policy.canonical_path(path)))
    except ValueError:
        path_cases.append(dict(path=path, ok=False))
for odd in [None, 5, 1.5, True, [], {}, ['C:' + B + 'a.exe']]:
    try:
        app_policy.canonical_path(odd)
        ok = True
    except ValueError:
        ok = False
    path_cases.append(dict(raw=odd, ok=ok))

good = [p['path'] for p in path_cases if p.get('ok') and 'path' in p]
rules_values = [None, {}, {'outbound': 'block'}, {'profile': 'gaming'}, {'outbound': 'allow', 'profile': 'call'}, {'outbound': 'BLOCK'}, {'outbound': True},
                {'profile': 'game'}, {'profile': 5}, {'extra': 1}, {'outbound': 'allow', 'profile': 'bulk'}, [], 'x', {'outbound': ['allow']},
                {'profile': 'streaming', 'outbound': 'block'}, {'profile': None}, {'outbound': None}]
a_exe = 'C:' + B + 'a.exe'
configs = [{}, {'protection_enabled': False}, {'protection_enabled': 1}, {'protection_enabled': None}, {'default_app_profile': 'bulk'},
           {'default_app_profile': 'gaming'}, {'default_app_profile': 'game'}, {'default_app_profile': 4}, {'app_rules': None}, {'app_rules': []},
           {'app_rules': {}}, [], None, 'x', {'unknown': 1}, {'app_rules': {a_exe: {}, 'c:/A.EXE': {}}},
           {'app_rules': {a_exe: {}, 'c:/A.EXE': {'outbound': 'block'}}}, {'app_rules': {a_exe: {'outbound': 'block'}, 'c:/A.EXE': {'outbound': 'block'}}},
           {'app_rules': {'C:' + B + str(i) + '.exe': {} for i in range(4096)}}, {'app_rules': {'C:' + B + str(i) + '.exe': {} for i in range(4097)}}]
for _ in range(900):
    rules = {}
    for _ in range(rng.randrange(0, 6)):
        key = rng.choice(good) if good and rng.random() < .8 else rng.choice(paths)
        rules[key] = rng.choice(rules_values)
    config = {'app_rules': rules}
    if rng.random() < .5:
        config['protection_enabled'] = rng.choice([True, False, True, False, 0, 'yes'])
    if rng.random() < .5:
        config['default_app_profile'] = rng.choice(list(app_policy.PROFILES) + ['nope', '', 3])
    configs.append(config)

apps = [None, {}, {'path': None}, {'path': 5}, {'path': 'notabs.exe'}, {'path': a_exe}, {'path': 'c:/A.EXE'}, {'path': 'D:' + B + 'Games' + B + 'Z.exe'},
        a_exe, {'path': 'C:' + B + '7.exe'}, {'path': B * 2 + 'srv' + B + 'share' + B + 'app.exe'}, {'path': a_exe + ' ', 'pid': 1},
        {'path': 'C:' + B + 'x.txt'}] + [{'path': p} for p in rng.sample(good, min(8, len(good)))]
contexts = [('tcp', 'example.com:443'), ('udp', '1.2.3.4:53'), ('icmp', 'a:1'), ('tcp', ''), ('tcp', None), ('tcp', 5), ('tcp', 'a' * 512), ('tcp', 'a' * 513),
            ('tcp', 'x\x00y'), (None, 'a:1'), ('TCP', 'a:1'), ('tcp', '\u00e9' * 512), ('tcp', '\u00e9' * 513)]
config_cases = []
for config in configs:
    try:
        policy = app_policy.PolicyEvaluator(config)
    except ValueError:
        config_cases.append(dict(config=config, ok=False))
        continue
    decisions = []
    for app in apps + [{'path': k} for k in list(policy.rules)[:3]]:
        for protocol, destination in contexts:
            decisions.append(dict(app=app, protocol=protocol, destination=destination, out=policy.authorize(app, protocol, destination)))
    config_cases.append(dict(config=config, ok=True, snapshot=policy.snapshot(), digest=policy.digest(), decisions=decisions))

out = ROOT / 'native-edge' / 'apppolicy' / 'testdata' / 'vectors.json.gz'
out.parent.mkdir(parents=True, exist_ok=True)
with gzip.open(out, 'wt', encoding='utf-8', compresslevel=9) as stream:
    json.dump(dict(paths=path_cases, configs=config_cases), stream, ensure_ascii=True)
print(json.dumps(dict(paths=len(path_cases), path_ok=sum(1 for c in path_cases if c['ok']), configs=len(config_cases),
                      config_ok=sum(1 for c in config_cases if c['ok']), bytes=out.stat().st_size)))
