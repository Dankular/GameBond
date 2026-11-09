"""Observe the running single-link VPN without restarting or reconfiguring it.

Each sample uses the captured System32 curl exit-IP check, records process
resources and the daemon's path counters, and persists failures as evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.atomic_io import read_json_shared, replace_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--duration', type=float, default=600)
    parser.add_argument('--interval', type=float, default=15)
    parser.add_argument('--label', default='single-link-soak')
    args = parser.parse_args()
    if args.duration <= 0 or args.interval < 1 or Path(args.label).name != args.label:
        parser.error('use a positive duration, interval >= 1, and a filename label')
    directory = ROOT / 'evidence'
    directory.mkdir(exist_ok=True)
    target = directory / (args.label + '.json')
    sample_file = directory / (args.label + '-latest-check.json')
    status_path = ROOT / '.runtime/userspace-status.json'
    first = read_json_shared(status_path)
    process = psutil.Process(first['pid'])
    executable = Path(process.exe())
    record = dict(started_at=time.time(), requested_seconds=args.duration,
                  interval_seconds=args.interval, state='running', samples=[],
                  daemon_pid=first['pid'], tunnel_created=first['created'],
                  executable=str(executable), sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
    start = time.monotonic()
    before_cpu = sum(process.cpu_times()[:2])
    previous_time = start

    def save():
        temporary = target.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(record, indent=2) + '\n')
        replace_file(temporary, target)

    save()
    try:
        while True:
            index = len(record['samples'])
            sample = dict(index=index, observed_at=time.time())
            result = subprocess.run([sys.executable, str(ROOT / 'tools/check_single_link_vpn.py'),
                                     '--output', str(sample_file)], capture_output=True, text=True, timeout=35)
            if result.returncode == 0:
                sample.update(read_json_shared(sample_file))
                try:
                    status = read_json_shared(status_path)
                    if status['pid'] != first['pid'] or status['created'] != first['created']:
                        raise RuntimeError('the tunnel session changed during observation')
                    sample['paths'] = status['transport']['paths']
                    sample['packets'] = status['packets']
                    sample['rss_bytes'] = process.memory_info().rss
                    current_cpu, current_time = sum(process.cpu_times()[:2]), time.monotonic()
                    sample['cpu_percent_one_core'] = 100 * (current_cpu - before_cpu) / max(.001, current_time - previous_time)
                    before_cpu, previous_time = current_cpu, current_time
                except (OSError, psutil.Error, ValueError, RuntimeError) as error:
                    sample.update(status='failed', error=str(error))
            else:
                sample.update(status='failed', error=(result.stderr or result.stdout)[-4000:])
            record['samples'].append(sample)
            record['elapsed_seconds'] = time.monotonic() - start
            save()
            print(json.dumps(dict(index=index, status=sample['status'], elapsed_seconds=round(record['elapsed_seconds'], 1))), flush=True)
            if record['elapsed_seconds'] >= args.duration:
                break
            time.sleep(min(args.interval, args.duration - record['elapsed_seconds']))
        record['state'] = 'passed' if all(s['status'] == 'ok' for s in record['samples']) else 'failed'
        record['finished_at'] = time.time()
        save()
        if record['state'] != 'passed':
            raise SystemExit(1)
    except BaseException:
        if record['state'] == 'running':
            record.update(state='interrupted', finished_at=time.time(), elapsed_seconds=time.monotonic() - start)
            save()
        raise


if __name__ == '__main__':
    main()
