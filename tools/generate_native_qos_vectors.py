"""Generate Go compatibility vectors from gamebond.adaptive_qos.AdaptiveQoS.

Seeded random transport snapshots and transmission decisions on a fake clock.
native-edge/bond must reproduce per-path quality, redundancy reasons/holds and
every replicate decision, including the duplicate-bandwidth budget.
"""
import gzip
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.adaptive_qos import AdaptiveQoS, QoSSettings  # noqa: E402
from gamebond.policy import Classification, QueuePolicy  # noqa: E402


class Clock:
    now = 1000.


def snapshot(rng, state):
    paths = []
    for slot in range(rng.choice([1, 2, 2, 3])):
        s = state.setdefault(slot, dict(expired=0, acked=0, lost=0, packed=0, delivered=0, seen=0, missed=0))
        s['expired'] += rng.choice([0, 0, 1, 5]); s['acked'] += rng.randrange(0, 200)
        s['lost'] += rng.choice([0, 0, 1, 3]); s['packed'] += rng.randrange(0, 40)
        s['delivered'] += rng.choice([0, 1000, 50000])
        s['seen'] += rng.choice([0, 3, 5, 40]); s['missed'] += rng.choice([0, 0, 1, 3, 6])
        path = dict(slot=slot, local=f'10.0.0.{slot}', remote='198.51.100.1:9000', healthy=rng.random() > .1,
                    rtt_ms=rng.choice([None, 4., 20., 80.]), rtt_jitter_ms=rng.choice([0, 1.5, 9., None]),
                    bonding=dict(expired_packets=s['expired'], acked_packets=s['acked'], delivered_bytes=s['delivered'],
                                 settled_loss_ratio=rng.choice([0, .01, .05, 2, -1]), queue_delay_ms=rng.choice([0, 3, 50])),
                    probe_quality=dict(lost=s['lost'], acked=s['packed']), peer_copy_quality=dict(seen=s['seen'], missed=s['missed']))
        if rng.random() < .1:
            path['available'] = False
        if rng.random() < .05:
            path['enabled'] = False
        if rng.random() < .1:
            del path['peer_copy_quality']
        paths.append(path)
    return dict(paths=paths)


def main():
    rng = random.Random(77)
    scenarios = []
    for sc in range(40):
        kw = {}
        if sc % 3 == 1:
            kw = dict(loss_threshold=rng.choice([.01, .05, .5]), jitter_threshold_ms=rng.choice([2, 8, 30]), recovery_seconds=rng.choice([.5, 3, 10]),
                      call_deadline_ms=rng.choice([10, 60, 400]), stream_deadline_ms=rng.choice([30, 120]), duplicate_mbps=rng.choice([.01, .2, 4, 50]))
        if sc % 10 == 9:
            kw['enabled'] = False
        settings = QoSSettings(**kw)
        clock = Clock(); clock.now = 1000.
        qos = AdaptiveQoS(settings, clock=lambda: Clock.now)
        state, steps = {}, []
        for _ in range(120):
            Clock.now += rng.choice([.001, .05, .2, .5, 1.5])
            if rng.random() < .4:
                snap = snapshot(rng, state)
                qos.observe(snap, Clock.now)
                steps.append(dict(op='observe', t=Clock.now, snapshot=snap, quality=[dict(x) for x in qos.quality], reasons={k: list(v) for k, v in qos.reasons.items()}, healthy=qos.healthy,
                                  active={p: qos.healthy > 1 and Clock.now < u for p, u in qos.redundancy_until.items()}))
            else:
                tag = rng.choice([0, 18, 26, 46, 18, 26])
                size = rng.choice([60, 200, 800, 1200, 1400])
                base = QueuePolicy(True, tag == 46, 60, 128)
                dscp_cls = Classification(None, tag, base, 'x')
                prio, rep = qos.transmission(dscp_cls, size)
                steps.append(dict(op='tx', t=Clock.now, tag=tag, size=size, base=tag == 46, replicate=rep))
        scenarios.append(dict(settings=kw, steps=steps, counts=dict(qos.counts), samples=qos.samples))
    out = ROOT / 'native-edge/bond/testdata/qos-vectors.json.gz'
    with gzip.GzipFile(out, 'wb', mtime=0) as f:
        f.write(json.dumps(scenarios, sort_keys=True).encode())
    print(json.dumps(dict(scenarios=len(scenarios), steps=sum(len(s['steps']) for s in scenarios),
                          replicated=sum(s['counts'].get('replicated', 0) for s in scenarios), limited=sum(s['counts'].get('duplicate_budget_limited', 0) for s in scenarios))))


if __name__ == '__main__':
    main()
