"""Generate deterministic Go compatibility vectors from Python CopyLedger / MtuProber.

Pure simulated monotonic time and a seeded RNG. No sockets, routes, live clients
or VPS access. The Go port in native-edge/bond/path_quality.go must reproduce
every recorded result exactly.
"""
import gzip
import heapq
import itertools
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.path_quality import CopyLedger, MtuProber  # noqa: E402


def jsonable(value):
    if isinstance(value, tuple):
        return [jsonable(v) for v in value]
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


class LedgerTrace:
    def __init__(self, name, capacity=4096):
        self.ledger = CopyLedger(capacity)
        self.row = dict(kind='copy_ledger', name=name, capacity=capacity, operations=[])

    def call(self, method, *args):
        result = getattr(self.ledger, method)(*args)
        self.row['operations'].append(dict(method=method, args=jsonable(list(args)), result=jsonable(result)))
        return result

    def finish(self):
        self.call('stats')
        return self.row


def ledger_replicated(name, seed, packets, loss, late_every, capacity=4096):
    """Replicated traffic over three paths with loss and variable lag."""
    rng = random.Random(seed)
    trace = LedgerTrace(name, capacity)
    paths = ['a', 'b', 'c']
    events = []   # (time, order, kind, args)
    order = itertools.count()
    for sequence in range(packets):
        sent = sequence * .002
        expected = [p for p in paths if rng.random() < .93] or ['a']
        events.append((sent, next(order), 'first', (sequence, expected[0], expected, sent)))
        for identity in expected[1:]:
            if rng.random() >= loss:
                lag = rng.uniform(0, .02) + (rng.uniform(.2, .6) if late_every and sequence % late_every == 0 else 0)
                events.append((sent + lag, next(order), 'duplicate', (sequence, identity, sent + lag)))
        if sequence % 25 == 0:
            events.append((sent + .15, next(order), 'resolve', (sent + .15, .1)))
        if rng.random() < .01:   # repeat of an identity already seen: must be ignored
            events.append((sent + .001, next(order), 'duplicate', (sequence, expected[0], sent + .001)))
        if rng.random() < .01:   # unknown sequence
            events.append((sent + .001, next(order), 'duplicate', (packets + sequence, 'a', sent + .001)))
    heapq.heapify(events)
    while events:
        _, _, method, args = heapq.heappop(events)
        trace.call(method, *args)
    trace.call('resolve', packets * .002 + 10, .1)
    return trace.finish()


def ledger_reinsert_and_eviction():
    """Re-`first` of a pending sequence keeps its position; capacity evicts the oldest."""
    t = LedgerTrace('reinsert_keeps_position_and_capacity_evicts', capacity=4)
    for s in range(3):
        t.call('first', s, 'a', ['a', 'b'], s * .01)
    t.call('first', 1, 'b', ['a', 'b', 'c'], .5)      # same key: updated in place
    t.call('duplicate', 1, 'a', .51)
    t.call('first', 3, 'a', ['a', 'b'], .6)
    t.call('first', 4, 'a', ['a', 'b'], .61)          # exceeds capacity: oldest (0) evicted
    t.call('duplicate', 0, 'b', .62)                  # evicted: unknown
    t.call('resolve', 1.0, .1)
    t.call('duplicate', 3, 'b', 1.1)                  # late after being counted missed
    t.call('duplicate', 3, 'b', 1.2)                  # already reversed: unknown again
    for s in range(10, 16):                           # overflow the resolved table too
        t.call('first', s, 'a', ['a', 'b'], 2 + s * .01)
    t.call('resolve', 3.0, .1)
    t.call('duplicate', 10, 'b', 3.1)
    t.call('first', 99, 'a', ['a'], 4.0)              # single expected path: no outcome
    t.call('resolve', 5.0, .1)
    return t.finish()


class MtuTrace:
    def __init__(self, name, ceiling, floor):
        self.p = MtuProber(ceiling, floor)
        self.nonces = itertools.count(1)
        self.row = dict(kind='mtu_prober', name=name, ceiling=ceiling, floor=floor, operations=[])

    def due(self, now):
        sends = self.p.due(now, lambda: next(self.nonces))
        self.row['operations'].append(dict(method='due', args=[now], result=jsonable(sends)))
        return sends

    def acknowledge(self, nonce, size):
        result = self.p.acknowledge(nonce, size)
        self.row['operations'].append(dict(method='acknowledge', args=[nonce, size], result=result))
        return result

    def stats(self):
        self.row['operations'].append(dict(method='stats', args=[], result=self.p.stats()))

    def finish(self):
        self.stats()
        return self.row


def mtu_path(name, ceiling, floor, true_mtu, rtt=.03, seconds=200, silent=False, flap=None, step=.1):
    """Drive due() on a clock; the simulated path answers probes up to ``true_mtu``."""
    t = MtuTrace(name, ceiling, floor)
    inflight = []   # (arrive_at, nonce, size)
    now = 0.
    while now <= seconds:
        limit = flap(now) if flap else true_mtu
        while inflight and inflight[0][0] <= now:
            _, nonce, size = heapq.heappop(inflight)
            t.acknowledge(nonce, size)
        for nonce, size in t.due(now):
            if not silent and size <= limit:
                heapq.heappush(inflight, (now + rtt, nonce, size))
        if int(now * 10) % 150 == 0:
            t.stats()
        now = round(now + step, 6)
    # Stray and repeated acknowledgements must not change state.
    t.acknowledge(10**9, ceiling)
    t.acknowledge(1, ceiling)
    return t.finish()


def mtu_invalid_and_edges():
    t = MtuTrace('floor_equals_ceiling', 548, 548)
    t.due(0.)
    t.due(.5)
    t.due(1.0)
    return t.finish()


def main():
    rows = [
        ledger_replicated('replicated_three_paths_light_loss', 1, 6000, .05, 0),
        ledger_replicated('replicated_with_late_copies', 2, 6000, .1, 7),
        ledger_replicated('replicated_heavy_loss_small_capacity', 3, 3000, .4, 11, capacity=64),
        ledger_reinsert_and_eviction(),
        mtu_path('full_size_path', 1472, 548, 1472),
        mtu_path('limited_to_1344', 1472, 548, 1344),
        mtu_path('limited_to_548', 1472, 548, 548),
        mtu_path('silent_legacy_peer', 1472, 548, 0, silent=True),
        mtu_path('limited_then_widens_after_recheck', 1472, 548, 0, seconds=400,
                 flap=lambda now: 1200 if now < 130 else 1472),
        mtu_path('ceiling_1400_floor_1232', 1400, 1232, 1280),
        mtu_path('ceiling_not_on_ladder', 1450, 600, 1100),
        mtu_invalid_and_edges(),
    ]
    target = ROOT / 'native-edge/bond/testdata/path-quality-vectors.json.gz'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(gzip.compress((json.dumps(rows, separators=(',', ':')) + '\n').encode(), mtime=0))
    print(json.dumps(dict(traces=len(rows), operations=sum(len(r['operations']) for r in rows), bytes=target.stat().st_size,
                          final=[dict(name=r['name'], last=r['operations'][-1]['result']) for r in rows if r['kind'] == 'mtu_prober'])))


if __name__ == '__main__':
    main()
