"""Vectors for native-edge/appevents from the real gamebond.app_events.AppEventStore.

    python tools/generate_native_app_events_vectors.py

Scripted scenarios run against the Python store with a fake clock and a table
resolver; every operation's result, and the history file after each flush, is
recorded. The Go test replays the same operations and compares. Clock values
are multiples of 0.25 so float arithmetic is exact.
"""
import gzip
import json
import random
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond import app_events  # noqa: E402

rng = random.Random(0xA77E)
B = chr(92)
NAMES = ['game.exe', 'Chrome.exe', 'STRASSE.exe', 'maße.exe', 'İstanbul.exe', 'app.exe', 'Σigma.exe', 'x.exe']
DIRS = ['C:' + B + 'Games' + B, 'c:' + B + 'games' + B, 'C:' + B + 'Program Files' + B + 'Z' + B, 'D:' + B + 'STRAẞE' + B,
        'C:' + B + 'straße' + B, B * 2 + 'srv' + B + 'share' + B, 'C:' + B + 'École' + B, 'C:' + B + 'école' + B]
DESTS = ['example.com:443', '1.2.3.4:53', 'host:80', '[::1]:9', 'x' * 512]


def identity(pid, birth, path, name=None):
    return dict(pid=pid, created_at=float(birth) / 4, created_filetime=str(birth), path=path, name=name or path.split(B)[-1])


class Clock:
    def __init__(self):
        self.now = 1700000000.0

    def __call__(self):
        return self.now


def scenario(name, ops, *, app_limit=4096, event_limit=256, table=None, seed_file=None):
    table = dict(table or {})
    initial = dict(table)  # forget ops mutate the live table
    clock = Clock()
    directory = tempfile.TemporaryDirectory()
    path = Path(directory.name) / 'history.json'
    if seed_file is not None:
        path.write_text(seed_file, encoding='utf-8')

    def resolver(pid, birth):
        row = table.get('%s:%s' % (pid, birth))
        return dict(row) if row else None

    def build():
        return app_events.AppEventStore(path, resolver=resolver, clock=clock, app_limit=app_limit, event_limit=event_limit)

    try:
        store = build()
    except Exception:
        directory.cleanup()
        return dict(name=name, app_limit=app_limit, event_limit=event_limit, table=initial, seed_file=seed_file, ops=[], results=[], build_ok=False)
    results = []
    for op in ops:
        kind = op['op']
        if kind == 'observe':
            results.append(store.observe(op['record']))
        elif kind == 'remember':
            store.remember_authorized_owner(op['identity']); results.append(None)
        elif kind == 'usage':
            store.record_usage(op['record']); results.append(None)
        elif kind == 'traffic':
            results.append(store.traffic_snapshot(op['limit']))
        elif kind == 'snapshot':
            results.append(store.snapshot(op['after'], op['limit']))
        elif kind == 'tick':
            clock.now += op['dt']; results.append(None)
        elif kind == 'forget':
            for key in op['keys']:
                table.pop(key, None)
            results.append(None)
        elif kind == 'flush':
            store.flush()
            results.append(json.loads(path.read_text(encoding='utf-8')) if path.exists() else None)
        elif kind == 'reload':
            try:
                store = build(); results.append(store.snapshot(0, 256))
            except Exception:
                results.append('error')
        else:
            raise ValueError(kind)
    directory.cleanup()
    return dict(name=name, app_limit=app_limit, event_limit=event_limit, table=initial, seed_file=seed_file, ops=ops, results=results, build_ok=True)


def record(ident, proof=None, protocol='tcp', dest=None, **over):
    row = dict(type='app_activity', proof=proof or ('tcp_connect' if protocol == 'tcp' else 'udp_reply'), protocol=protocol,
               destination=dest or rng.choice(DESTS), pid=ident['pid'], created_filetime=ident['created_filetime'])
    row.update(over)
    return row


def usage_row(ident, **over):
    row = dict(pid=ident['pid'], created_filetime=ident['created_filetime'], uploaded_bytes=rng.randrange(0, 5000),
               downloaded_bytes=rng.randrange(0, 5000), active_connections=rng.randrange(0, 4), generation=1,
               destinations=[rng.choice(DESTS) for _ in range(rng.randrange(0, 3))])
    row.update(over)
    return row


scenarios = []

# 1. broad randomised mix over a pool of identities
for index in range(60):
    pool = []
    for _ in range(rng.randrange(2, 9)):
        birth = 133000000000000000 + rng.randrange(10 ** 6) * 1000 + 116444736000000000 - 116444736000000000
        pool.append(identity(rng.randrange(1, 500), birth, rng.choice(DIRS) + rng.choice(NAMES), rng.choice(NAMES)))
    table = {'%s:%s' % (i['pid'], i['created_filetime']): i for i in pool}
    ops = []
    for _ in range(rng.randrange(20, 80)):
        pick = rng.random()
        ident = rng.choice(pool)
        if pick < .30:
            ops.append(dict(op='observe', record=record(ident, protocol=rng.choice(['tcp', 'udp']))))
        elif pick < .38:
            bad = rng.choice([
                dict(proof='tcp_connect', protocol='udp'), dict(proof='udp_reply', protocol='tcp'), dict(proof='x'), dict(protocol='icmp'),
                dict(pid=0), dict(pid=-3), dict(pid=True), dict(pid='7'), dict(pid=1.5), dict(created_filetime='12a'), dict(created_filetime=''),
                dict(created_filetime='1' * 21), dict(created_filetime=5), dict(destination=7), dict(destination='d' * 513), dict(type='other'),
                dict(destination='é' * 512), dict(destination='é' * 513), dict(pid=10 ** 9, created_filetime='99')])
            ops.append(dict(op='observe', record=record(ident, **bad)))
        elif pick < .42:
            ops.append(dict(op='observe', record=rng.choice([None, 5, 'x', [], {}])))
        elif pick < .50:
            ops.append(dict(op='tick', dt=rng.choice([0, .25, 1, 29.75, 30, 30.25, 59.75, 60, 61, 100])))
        elif pick < .56:
            ops.append(dict(op='remember', identity=ident))
        elif pick < .60:
            ops.append(dict(op='forget', keys=['%s:%s' % (ident['pid'], ident['created_filetime'])]))
        elif pick < .80:
            rows = [usage_row(i, generation=rng.choice([1, 1, 2]), **rng.choice([{}, {}, dict(last_activity=rng.choice([5, 'now', None, 1.5]))]))
                    for i in rng.sample(pool, rng.randrange(1, len(pool) + 1))]
            if rng.random() < .3:
                rows.append(rng.choice([
                    usage_row(ident, uploaded_bytes=-1), usage_row(ident, generation=True), usage_row(ident, active_connections='3'),
                    usage_row(ident, destinations='x'), usage_row(ident, destinations=['a'] * 9), usage_row(ident, destinations=[5]),
                    usage_row(ident, destinations=['d' * 513]), 'junk', 5, dict(pid='x', created_filetime=1), usage_row(ident, pid=True),
                    usage_row(dict(pid=9999, created_filetime='1'))]))
            rec = dict(type='app_metrics', applications=rows)
            extra = rng.choice([{}, dict(skipped_identities=rng.randrange(0, 9)), dict(skipped_identities=-1), dict(skipped_identities=True),
                                dict(skipped_identities='4'), dict(skipped_identities=3)])
            rec.update(extra)
            ops.append(dict(op='usage', record=rec))
        elif pick < .83:
            ops.append(dict(op='usage', record=rng.choice([None, 'x', dict(type='app_metrics'), dict(type='app_metrics', applications='no'),
                                                           dict(type='other', applications=[]), dict(type='app_metrics', applications=[{}] * 65)])))
        elif pick < .90:
            ops.append(dict(op='snapshot', after=rng.choice([0, 0, 1, 2, 5, 100]), limit=rng.choice([0, 1, 3, 32, 256, 1000, -4])))
        elif pick < .94:
            ops.append(dict(op='traffic', limit=rng.choice([0, 1, 2, 128, 600, -1])))
        elif pick < .97:
            ops.append(dict(op='flush'))
        else:
            ops.append(dict(op='flush'))
            ops.append(dict(op='reload'))
    ops.append(dict(op='flush'))
    ops.append(dict(op='snapshot', after=0, limit=256))
    ops.append(dict(op='traffic', limit=512))
    limits = rng.choice([(4096, 256), (3, 2), (1, 1), (4, 256)])
    scenarios.append(scenario('mix-%d' % index, ops, app_limit=limits[0], event_limit=limits[1], table=table))

# 2. process cache bound (512) and eviction of the oldest identity
pool = [identity(i + 1, 133000000000000000 + i, 'C:' + B + 'p' + B + 'app%d.exe' % i) for i in range(600)]
ops = [dict(op='observe', record=record(i, dest='h:1')) for i in pool]
ops.append(dict(op='usage', record=dict(type='app_metrics', applications=[usage_row(pool[0], uploaded_bytes=10, downloaded_bytes=10), usage_row(pool[87], uploaded_bytes=11, downloaded_bytes=11), usage_row(pool[88], uploaded_bytes=12, downloaded_bytes=12), usage_row(pool[-1], uploaded_bytes=7, downloaded_bytes=3)])))
ops += [dict(op='snapshot', after=0, limit=256), dict(op='traffic', limit=128), dict(op='flush')]
scenarios.append(scenario('process-cache', ops, table={'%s:%s' % (i['pid'], i['created_filetime']): i for i in pool}))

# 3. a verified owner that exited while connect completed
ident = identity(77, 133000000000000123, 'C:' + B + 'Games' + B + 'gone.exe')
key = '%s:%s' % (ident['pid'], ident['created_filetime'])
ops = [dict(op='remember', identity=ident), dict(op='observe', record=record(ident)), dict(op='tick', dt=29.75),
       dict(op='observe', record=record(ident, protocol='udp')), dict(op='tick', dt=1), dict(op='observe', record=record(ident)),
       dict(op='tick', dt=100), dict(op='observe', record=record(ident)), dict(op='snapshot', after=0, limit=32)]
scenarios.append(scenario('authorized-owner', ops, table={}))
ops = [dict(op='remember', identity=ident), dict(op='tick', dt=30), dict(op='observe', record=record(ident)), dict(op='snapshot', after=0, limit=32)]
scenarios.append(scenario('authorized-owner-boundary', ops, table={}))

# 4. size trimming of snapshots (64 KiB) with very long paths
pool = [identity(i + 1, 133000000000000000 + i, 'C:' + B + ('d' * 3000) + B + 'app%d.exe' % i) for i in range(40)]
ops = [dict(op='observe', record=record(i, dest='h:1')) for i in pool]
ops += [dict(op='snapshot', after=0, limit=256), dict(op='snapshot', after=30, limit=256), dict(op='traffic', limit=512)]
scenarios.append(scenario('snapshot-size', ops, table={'%s:%s' % (i['pid'], i['created_filetime']): i for i in pool}))
rows = [usage_row(i, uploaded_bytes=5, downloaded_bytes=6) for i in pool[:30]]
ops = [dict(op='observe', record=record(i, dest='h:1')) for i in pool[:30]]
ops += [dict(op='usage', record=dict(type='app_metrics', applications=rows)), dict(op='traffic', limit=512), dict(op='traffic', limit=3)]
scenarios.append(scenario('traffic-size', ops, table={'%s:%s' % (i['pid'], i['created_filetime']): i for i in pool}))

# 5. history file validation and reload
ok_app = dict(path='C:' + B + 'a.exe', name='a.exe', first_seen=1.5, last_seen=2.5)
event = lambda n: dict(id=n, kind='new_app_tunnel_use', timestamp=1.5, application=dict(path='C:' + B + 'a.exe', name='a.exe'))
loads = {
    'good': dict(version=1, sequence=2, applications=[ok_app], events=[event(1), event(2)]),
    'version-float': dict(version=1.0, sequence=0, applications=[], events=[]),
    'version-true': dict(version=True, sequence=0, applications=[], events=[]),
    'version-2': dict(version=2, sequence=0, applications=[], events=[]),
    'no-version': dict(sequence=0),
    'only-version': dict(version=1),
    'sequence-str': dict(version=1, sequence='3', applications=[], events=[]),
    'sequence-bool': dict(version=1, sequence=True, applications=[], events=[]),
    'sequence-negative': dict(version=1, sequence=-1, applications=[], events=[]),
    'sequence-float': dict(version=1, sequence=2.0, applications=[], events=[]),
    'apps-not-list': dict(version=1, applications={}, events=[]),
    'events-not-list': dict(version=1, applications=[], events={}),
    'too-many-events': dict(version=1, sequence=300, applications=[], events=[event(i + 1) for i in range(257)]),
    'event-ids-not-increasing': dict(version=1, sequence=5, applications=[], events=[event(2), event(2)]),
    'event-id-above-sequence': dict(version=1, sequence=1, applications=[], events=[event(2)]),
    'event-id-bool': dict(version=1, sequence=5, applications=[], events=[dict(event(1), id=True)]),
    'event-kind': dict(version=1, sequence=5, applications=[], events=[dict(event(1), kind='x')]),
    'event-application': dict(version=1, sequence=5, applications=[], events=[dict(event(1), application=[])]),
    'event-not-dict': dict(version=1, sequence=5, applications=[], events=[7]),
    'app-relative-path': dict(version=1, applications=[dict(path='a.exe')], events=[]),
    'app-no-path': dict(version=1, applications=[dict(name='a')], events=[]),
    'app-path-int': dict(version=1, applications=[dict(path=5)], events=[]),
    'app-not-dict': dict(version=1, applications=['x'], events=[]),
    'app-unc': dict(version=1, applications=[dict(path=B * 2 + 'srv' + B + 'x.exe')], events=[]),
    'app-rooted': dict(version=1, applications=[dict(path=B + 'x.exe')], events=[]),
    'app-drive-relative': dict(version=1, applications=[dict(path='C:x.exe')], events=[]),
    'case-collision': dict(version=1, applications=[dict(ok_app), dict(ok_app, path='c:' + B + 'A.EXE')], events=[]),
}
for label, content in loads.items():
    scenarios.append(scenario('load-' + label, [dict(op='snapshot', after=0, limit=256), dict(op='traffic', limit=8)], seed_file=json.dumps(content)))
scenarios.append(scenario('load-garbage', [dict(op='snapshot', after=0, limit=256)], seed_file='not json'))
scenarios.append(scenario('load-huge', [dict(op='snapshot', after=0, limit=256)], seed_file=' ' * (4 * 1024 * 1024 + 1)))
scenarios.append(scenario('load-known-continues', [
    dict(op='observe', record=record(identity(1, 133000000000000001, 'C:' + B + 'A.EXE'))), dict(op='tick', dt=61),
    dict(op='observe', record=record(identity(1, 133000000000000001, 'C:' + B + 'A.EXE'))), dict(op='flush'), dict(op='snapshot', after=0, limit=32)],
    table={'1:133000000000000001': identity(1, 133000000000000001, 'C:' + B + 'A.EXE')},
    seed_file=json.dumps(dict(version=1, sequence=2, applications=[ok_app], events=[event(1), event(2)]))))
too_many = dict(version=1, applications=[dict(path='C:' + B + '%d.exe' % i) for i in range(5)], events=[])
scenarios.append(scenario('load-app-limit', [dict(op='snapshot', after=0, limit=1)], app_limit=4, seed_file=json.dumps(too_many)))

out = ROOT / 'native-edge' / 'appevents' / 'testdata' / 'vectors.json.gz'
out.parent.mkdir(parents=True, exist_ok=True)
with gzip.open(out, 'wt', encoding='utf-8', compresslevel=9) as stream:
    json.dump(scenarios, stream, ensure_ascii=True)
events = sum(1 for s in scenarios for op, r in zip(s['ops'], s['results']) if op['op'] == 'observe' and r)
print(json.dumps(dict(scenarios=len(scenarios), ops=sum(len(s['ops']) for s in scenarios), new_app_events=events, bytes=out.stat().st_size)))
