"""Read-only smoke check of the running single-link VPN using captured curl.

Checks the public exit IP and daemon packet counters. It never starts/stops a
client, edits config, or changes adapters. The System32 curl must be captured.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.atomic_io import read_json_shared


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--status', type=Path, default=ROOT / '.runtime/userspace-status.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/single-link-vpn.json')
    args = parser.parse_args()

    def status():
        deadline = time.monotonic() + 1.5
        while True:
            try:
                doc = read_json_shared(args.status)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.02)
        assert doc['state'] == 'running', doc['state']
        assert time.time() - doc['updated_at'] < 5, 'daemon status is stale'
        assert len(doc['transport']['paths']) == 1, 'this check requires one configured link'
        assert doc['transport']['paths'][0]['healthy'], 'link is unhealthy'
        return doc

    before = status()
    curl = str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/curl.exe') if os.name == 'nt' else 'curl'
    result = subprocess.run([curl, '--silent', '--show-error', '--fail', '--max-time', '20', 'https://api.ipify.org'], capture_output=True, text=True, timeout=25, check=True)
    exit_ip = result.stdout.strip()
    assert exit_ip == before['peer'][0], f'exit IP {exit_ip} differs from VPN server {before["peer"][0]}'
    deadline = time.monotonic() + 6
    while True:
        after = status()
        assert after['pid'] == before['pid'], 'daemon restarted during check'
        deltas = {k: after['packets'][k] - before['packets'][k] for k in ('outbound', 'injected')}
        if all(v > 0 for v in deltas.values()):
            break
        assert time.monotonic() < deadline, f'no bidirectional tunnel traffic: {deltas}'
        time.sleep(.1)
    record = dict(status='ok', exit_ip=exit_ip, healthy_paths=1, packet_deltas=deltas,
                  backend=after.get('backend'), daemon_pid=after['pid'], observed_at=time.time())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
