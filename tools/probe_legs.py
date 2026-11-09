"""Benchmark each leg of the connection in isolation, so a hidden slowdown shows
up as one leg falling out of line with its neighbours.

Legs, innermost first:
  1 raw_udp         bare UDP socket pair, no protocol           (leg-probe loopback)
  2 codec_cpu       GB03 seal/open + reorder cost, no I/O       (go test -bench)
  3 logic_virtual   Sender+Receiver on a virtual clock, ideal wire: the protocol
                    logic's own ceiling, with and without a link policy
  4 go_to_go        real sockets, Go client -> Go server
  5 go_to_python    real sockets, Go client -> Python server
  6 remote_udp      (opt-in --remote HOST:PORT) raw UDP to a far host running
                    `leg-probe serve`: RTT, jitter, loss, throughput
  7 tunnel          (opt-in --tunnel) tools/benchmark_tunnel.py through the live
                    client and VPS; touches the real tunnel and the VPS

Every number is also expressed as a fraction of the leg below it, which is where
a slowdown hides (for example bonded Go gets 65% of the raw socket). Loopback
legs 1-5 show implementation limits on this machine only, not link behaviour.

    python tools/probe_legs.py --label before-change
    python tools/probe_legs.py --label after-change --baseline before-change

Build first, for leg-probe, client-probe and receiver-probe:
    go -C native-edge build -o ../build/gamebond-native-<name>.exe ./cmd/<name>
"""
import argparse
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'evidence'
TOLERANCE = .15     # a leg more than 15% worse than its baseline is flagged
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def run(command, cwd=ROOT, env=None, timeout=300):
    merged = dict(os.environ, GOFLAGS='-buildvcs=false', **(env or {}))
    return subprocess.run(command, capture_output=True, text=True, creationflags=NO_WINDOW, cwd=cwd, env=merged, timeout=timeout)


def exe(name):
    return str(ROOT / 'build' / (f'gamebond-native-{name}.exe' if sys.platform == 'win32' else f'gamebond-native-{name}'))


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        if line.startswith('{'):
            return json.loads(line)
    raise RuntimeError('no JSON in output: ' + text[-400:])


def median(runs, key):
    values = [r[key] for r in runs if r.get(key) is not None]
    return round(statistics.median(values), 2) if values else None


def leg_raw_udp(repeats):
    runs = [last_json(run([exe('leg-probe'), 'loopback', '-seconds', '2']).stdout) for _ in range(repeats)]
    return dict(mbit=median(runs, 'mbit_per_s'), loss_percent=median(runs, 'loss_percent'),
                rtt_p99_ms=median(runs, 'RTTP99Ms'), jitter_ms=median(runs, 'jitter_ms'))


def leg_codec_cpu():
    out = run(['go', 'test', './bond', '-run', 'x', '-bench', 'Codec|OrderedReceive', '-benchtime', '1s'], cwd=ROOT / 'native-edge').stdout
    found = {m.group(1): float(m.group(2)) for m in re.finditer(r'^Benchmark(\w+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op', out, re.M)}
    return dict(ns_per_op=found, mbit_equivalent={k: round(1113 * 8 / v * 1000, 1) for k, v in found.items() if v})


def leg_logic_virtual():
    out = run(['go', 'test', './bond', '-run', 'VirtualThroughputReport', '-count=1', '-v'], cwd=ROOT / 'native-edge', env=dict(GB_VIRTUAL='1')).stdout
    rows = {}
    for m in re.finditer(r'uplinks=(\d+) policy=([\d.]+) rate=\d+ -> ([\d.]+) Mbit/s', out):
        rows[f'uplinks{m.group(1)}_policy{m.group(2)}'] = float(m.group(3))
    return dict(mbit=rows)


def leg_go_to_go(repeats):
    base = [sys.executable, str(ROOT / 'tools/check_go_to_go.py'), '--send', '30000', '--rate', '4000']
    plain = [last_json(run(base).stdout) for _ in range(repeats)]
    paced = [last_json(run(base + ['--policy', '--policy-mbps', '50']).stdout) for _ in range(repeats)]
    return dict(mbit=median(plain, 'mbit_per_s'), delivered=median(plain, 'server_payloads'),
                policy50_mbit=median(paced, 'mbit_per_s'), policy50_delivered=median(paced, 'server_payloads'))


def leg_go_to_python(repeats):
    cmd = [sys.executable, str(ROOT / 'tools/check_native_client.py'), '--send', '20000', '--rate', '1000', '--no-evidence']
    runs = [last_json(run(cmd).stdout) for _ in range(repeats)]
    return dict(mbit=median(runs, 'mbit_per_s'))


def leg_remote(target):
    return last_json(run([exe('leg-probe'), 'measure', '-target', target, '-seconds', '3']).stdout)


def leg_tunnel(label):
    result = run([sys.executable, str(ROOT / 'tools/benchmark_tunnel.py'), '--label', label, '--impl', 'go'], timeout=900)
    return dict(returncode=result.returncode, tail=(result.stdout + result.stderr)[-600:])


def flatten(value, prefix=''):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from flatten(v, f'{prefix}{k}.')
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield prefix[:-1], value


LOWER_IS_BETTER = ('loss', 'rtt', 'jitter', 'ns_per_op')   # every other metric: higher is better


def compare(now, before):
    old, flagged = dict(flatten(before)), []
    for key, value in flatten(now):
        if key not in old or not old[key]:
            continue
        lower = any(word in key for word in LOWER_IS_BETTER)
        change = (value - old[key]) / old[key]
        if (change > TOLERANCE if lower else change < -TOLERANCE):
            flagged.append(dict(metric=key, before=old[key], now=value, change_percent=round(change * 100, 1)))
    return flagged


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--label', required=True)
    parser.add_argument('--baseline')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--remote', metavar='HOST:PORT', help='raw UDP leg to a far host running leg-probe serve')
    parser.add_argument('--tunnel', action='store_true', help='also run benchmark_tunnel.py (live tunnel and VPS)')
    parser.add_argument('--skip', nargs='*', default=[], choices=['raw_udp', 'codec_cpu', 'logic_virtual', 'go_to_go', 'go_to_python'])
    args = parser.parse_args()
    legs = {}
    steps = [('raw_udp', lambda: leg_raw_udp(args.repeats)), ('codec_cpu', leg_codec_cpu), ('logic_virtual', leg_logic_virtual),
             ('go_to_go', lambda: leg_go_to_go(args.repeats)), ('go_to_python', lambda: leg_go_to_python(args.repeats))]
    for name, fn in steps:
        if name not in args.skip:
            print(f'[{name}] ...', file=sys.stderr, flush=True)
            legs[name] = fn()
    if args.remote:
        legs['remote_udp'] = leg_remote(args.remote)
    if args.tunnel:
        legs['tunnel'] = leg_tunnel(args.label)
    ratios = {}
    raw = legs.get('raw_udp', {}).get('mbit')
    if raw and legs.get('go_to_go', {}).get('mbit'):
        ratios['go_to_go_vs_raw_socket'] = round(legs['go_to_go']['mbit'] / raw, 2)
    virtual = legs.get('logic_virtual', {}).get('mbit', {}).get('uplinks2_policy50')
    if virtual and legs.get('go_to_go', {}).get('policy50_mbit'):
        ratios['paced_real_vs_virtual_logic'] = round(legs['go_to_go']['policy50_mbit'] / virtual, 2)
    if legs.get('go_to_go', {}).get('mbit') and legs.get('go_to_python', {}).get('mbit'):
        ratios['python_server_vs_go_server'] = round(legs['go_to_python']['mbit'] / legs['go_to_go']['mbit'], 2)
    record = dict(label=args.label, scope='loopback legs on one machine unless remote_udp/tunnel are present', legs=legs, ratios=ratios)
    regressions = []
    if args.baseline:
        previous = json.loads((EVIDENCE / f'legs-{args.baseline}.json').read_text())
        regressions = compare(legs, previous['legs'])
        record['regressions_vs_' + args.baseline] = regressions
    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / f'legs-{args.label}.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    if regressions:
        print(f'\nREGRESSIONS (more than {int(TOLERANCE * 100)}% worse): {len(regressions)}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
