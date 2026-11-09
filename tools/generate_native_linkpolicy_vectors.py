"""Generate Go compatibility vectors from Python LinkPolicy / UsageLedger.

Seeded, fake clock, temp files only. native-edge/linkpolicy must reproduce
cycle_start, effective(), per-link usage over many days, and must read the
ledger file Python wrote.
"""
import gzip
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import random
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.link_policy import LinkPolicy, UsageLedger, cycle_start  # noqa: E402


def main():
    rng = random.Random(11)
    cycles = [dict(day=d.isoformat(), reset_day=r, start=cycle_start(d, r).isoformat())
              for d in (date(2024, 1, 1) + timedelta(days=rng.randrange(0, 1000)) for _ in range(300))
              for r in (rng.choice([1, 15, 28, 29, 30, 31]),)]
    policies, effective = [], []
    for _ in range(300):
        kw = dict(role=rng.choice(['primary', 'secondary', 'backup', 'never']), upload_mbps=rng.choice([0, 5, 50.5]),
                  download_mbps=rng.choice([0, 7, 100]), daily_bytes=rng.choice([0, 1000, 10**6]), monthly_bytes=rng.choice([0, 5000, 10**7]),
                  reset_day=rng.randrange(1, 32), overlimit=rng.choice(['stop', 'throttle']), overlimit_mbps=rng.choice([.2, 1, 3]))
        usage = dict(daily_bytes=rng.choice([0, 999, 1000, 10**6 + 1]), monthly_bytes=rng.choice([0, 4999, 5000, 10**8]))
        e = LinkPolicy(**kw).effective(usage)
        effective.append(dict(policy=kw, usage=usage, result=e))
    bad = []
    for kw in (dict(role='x'), dict(upload_mbps=-1), dict(upload_mbps=10001), dict(reset_day=0), dict(reset_day=32), dict(overlimit='y'),
               dict(daily_bytes=-1), dict(overlimit='throttle', overlimit_mbps=0), dict(download_mbps=float('inf'))):
        try:
            LinkPolicy(**kw)
            raise SystemExit(f'expected rejection of {kw}')
        except ValueError:
            bad.append({k: (None if isinstance(v, float) and v != v or v in (float('inf'),) else v) for k, v in kw.items()})
    clock = [datetime(2024, 1, 20, 12, tzinfo=timezone.utc)]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'link-usage.json'
        ledger = UsageLedger(path, clock=lambda: clock[0])
        ops, checks = [], []
        for step in range(500):
            if step % 5 == 0:
                clock[0] += timedelta(hours=rng.choice([1, 12, 24, 30, 70]))
            key = rng.choice(['0', '1', '2'])
            up, down = rng.randrange(0, 2000), rng.randrange(0, 4000)
            ledger.add(key, up, down)
            ops.append(dict(day=clock[0].date().isoformat(), key=key, upload=up, download=down))
            if step % 9 == 0:
                for k in ('0', '1', '2'):
                    for reset in (1, 15, 31):
                        u = ledger.usage(k, LinkPolicy(reset_day=reset))
                        checks.append(dict(after=step, day=clock[0].date().isoformat(), key=k, reset_day=reset, usage=u))
        ledger.save()
        file_text = path.read_text()
    out = ROOT / 'native-edge/linkpolicy/testdata/linkpolicy-vectors.json.gz'
    out.parent.mkdir(exist_ok=True)
    with gzip.open(out, 'wt') as f:
        json.dump(dict(cycles=cycles, effective=effective, rejected=bad, ops=ops, checks=checks, ledger_file=file_text), f)
    print(len(cycles), 'cycles', len(effective), 'effective', len(ops), 'ops', len(checks), 'usage checks;', sum(e['result']['blocked'] for e in effective), 'blocked')


if __name__ == '__main__':
    main()
