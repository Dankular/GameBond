"""Write native-edge/capture/testdata/vectors.json.gz from gamebond.capture."""
import gzip
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.capture import normalize_apps, proxy_configuration  # noqa: E402

rng = random.Random(20260509)
PIECES = [
    'C:\\Games\\cod.exe', 'c:/games/COD.EXE', 'C:\\Games\\..\\Games\\cod.exe', '  C:\\a b\\x.exe  ', 'D:\\x\\.\\y\\z.Exe',
    'C:\\\\double\\\\slash.exe', '\\\\server\\share\\app.exe', 'relative\\app.exe', 'C:app.exe', '\\rooted\\app.exe',
    'C:\\noext', 'C:\\Games\\cod.exe.txt', 'C:\\x\\a\0b.exe', '', ' ', 'C:\\ÄÖ\\straße.exe', 'C:\\STRASSE\\x.exe',
    'C:\\straße\\x.exe', 'C:\\Games\\\u00a0cod.exe', '\tC:\\t\\t.exe\n', 'E:/mixed/sep\\ok.exe', 'C:\\a\\..\\..\\b.exe',
]


def run(items):
    try:
        return {'ok': normalize_apps(items)}
    except ValueError as e:
        return {'error': str(e)}


cases = []
for _ in range(400):
    items = [rng.choice(PIECES) if rng.random() < .8 else rng.choice([5, None, 1.5, ['x']]) for _ in range(rng.randint(0, 5))]
    cases.append({'in': items, 'out': run(items)})
for p in PIECES:
    cases.append({'in': [p], 'out': run([p])})

configs = []
root = 'C:\\Proj\\Speedify'
for mode in (None, 'all', 'selected', 'bogus'):
    for apps in ([], ['C:\\Games\\cod.exe'], ['C:\\a.exe', 'c:\\A.EXE', 'C:\\b.exe'], ['bad'], None):
        for ns in (None, 'C:\\x\\ns.exe', 'C:\\Proj\\Speedify\\build\\gamebond-netstack.exe'):
            cfg = {}
            if mode is not None:
                cfg['capture_mode'] = mode
            if apps is not None:
                cfg['cod_executables'] = apps
            exe = 'C:\\Py\\python.exe' if ns != 'C:\\x\\ns.exe' else 'C:\\Py\\other.exe'
            try:
                out = {'ok': proxy_configuration(cfg, '127.0.0.1:1080', root, exe, ns)}
            except ValueError as e:
                out = {'error': str(e)}
            carrier = Path(exe)
            configs.append({'config': cfg, 'netstack': ns,
                            'carriers': [str(carrier), str(carrier.with_name('python.exe')), str(carrier.with_name('pythonw.exe'))],
                            'out': out})
dest = ROOT / 'native-edge/capture/testdata'
dest.mkdir(parents=True, exist_ok=True)
with gzip.open(dest / 'vectors.json.gz', 'wt', encoding='utf-8') as f:
    json.dump({'root': root, 'normalize': cases, 'configs': configs}, f, ensure_ascii=False, sort_keys=True)
print(len(cases), len(configs))
