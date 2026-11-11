"""Generate Go compatibility vectors from gamebond.network_scanner (pure parts).

normalize_inventory, validate_scan and DeviceHistory over seeded random inputs,
including malformed rows, duplicates, limit overflow and a history file that
Go must read and rewrite compatibly.
"""
import gzip
import json
from pathlib import Path
import random
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.network_scanner import DeviceHistory, normalize_inventory, validate_scan  # noqa: E402


def rand_ip(rng):
    return rng.choice(['192.168.1.%d' % rng.randrange(0, 256), '10.0.%d.%d' % (rng.randrange(0, 4), rng.randrange(0, 256)), '172.16.5.%d' % rng.randrange(1, 255),
                       '169.254.1.1', '127.0.0.1', '0.0.0.0', '224.0.0.5', '255.255.255.255', 'not-an-ip', '8.8.8.%d' % rng.randrange(1, 9)])


def adapter_row(rng):
    row = dict(index=rng.choice([1, 5, 12, '7', 'x', None]), name=rng.choice(['Ethernet', 'Wi-Fi', 3, None]), address=rand_ip(rng),
               prefix_length=rng.choice([8, 16, 20, 24, 25, 30, 32, '24', 33, -1, 'x']), up=rng.choice([True, False, 'Up', 0, 1]),
               mac=rng.choice(['AA-BB-CC-DD-EE-FF', '', None, 'aa:bb']), description=rng.choice(['Realtek', None, '']))
    for key in rng.sample(list(row), rng.choice([0, 0, 0, 0, 1])):
        del row[key]
    return row


def neighbor_row(rng):
    row = dict(interface_index=rng.choice([1, 5, 12, '7', 'x']), address=rand_ip(rng),
               mac=rng.choice(['AA-BB-CC-DD-EE-01', 'aa:bb:cc:dd:ee:02', '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF', '', None]),
               state=rng.choice(['Reachable', 'Stale', 'Delay', 'Probe', 'Incomplete', 'UNREACHABLE', 'Permanent', 7]))
    for key in rng.sample(list(row), rng.choice([0, 0, 0, 0, 1])):
        del row[key]
    return row


def main():
    rng = random.Random(31)
    inventories = []
    for i in range(300):
        na, nn = rng.choice([0, 3, 10]), rng.choice([0, 6, 40])
        record = dict(adapters=[adapter_row(rng) for _ in range(na)], neighbors=[neighbor_row(rng) for _ in range(nn)])
        out = normalize_inventory(record)
        out.pop('observed_at')
        inventories.append(dict(record=record, result=out))
    big = dict(adapters=[dict(index=i, name='a%d' % i, address='10.1.%d.%d' % (i // 250, i % 250 + 1), prefix_length=24, up=True) for i in range(140)],
               neighbors=[dict(interface_index=1, address='10.2.%d.%d' % (i // 250, i % 250 + 1), mac='aa-bb-cc-00-%02x-%02x' % (i // 256, i % 256), state='Stale') for i in range(4100)])
    out = normalize_inventory(big)
    out.pop('observed_at')
    inventories.append(dict(record=big, result=out))

    adapters = [dict(index=3, name='E', address='192.168.1.10', prefix_length=24, subnet='192.168.1.0/24', up=True),
                dict(index=4, name='W', address='10.0.5.7', prefix_length=16, subnet='10.0.0.0/16', up=True),
                dict(index=5, name='D', address='192.168.9.9', prefix_length=24, subnet='192.168.9.0/24', up=False),
                dict(index=6, name='S', address='172.20.1.1', prefix_length=30, subnet='172.20.1.0/30', up=True)]
    scans = []
    for subnet in ['192.168.1.0/24', '192.168.1.0/25', '192.168.1.8/29', '192.168.0.0/23', '10.0.5.0/24', '10.0.0.0/16', '10.0.5.0/23', '8.8.8.0/24', '192.168.1.1/24', '192.168.9.0/24',
                   '172.20.1.0/30', '172.20.1.4/30', '172.20.1.10/32', '192.168.1.10/31', 'garbage']:
        for source, index in [('192.168.1.10', 3), ('10.0.5.7', 4), ('192.168.9.9', 5), ('172.20.1.1', 6), ('192.168.1.11', 3), ('192.168.1.10', 9)]:
            for max_hosts in (256, 100, 0):
                row = dict(subnet=subnet, source=source, index=index, max_hosts=max_hosts)
                try:
                    src, targets = validate_scan(subnet, source, index, adapters, max_hosts)
                    row.update(ok=True, source_out=src, targets=targets)
                except (ValueError, TypeError):
                    row.update(ok=False)
                scans.append(row)

    histories = []
    for sc in range(20):
        limit = rng.choice([3, 10, 4096])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'h.json'
            history = DeviceHistory(path, limit)
            rounds = []
            t = 1000.0
            for _ in range(12):
                t += rng.choice([0, 5, 100])
                devices = [dict(interface_index=rng.choice([1, 2]), address='192.168.1.%d' % rng.randrange(1, 12), mac=rng.choice(['aa:bb:cc:00:00:%02x' % rng.randrange(0, 12), '']))
                           for _ in range(rng.randrange(0, 8))]
                obs_t = t - rng.choice([0, 0, 50])
                rows = history.observe(devices, obs_t)
                rounds.append(dict(devices=devices, t=obs_t, rows=rows))
            histories.append(dict(limit=limit, rounds=rounds, records=history.records, file=json.loads(path.read_text())))
    out = ROOT / 'native-edge/scanner/testdata/scanner-vectors.json.gz'
    out.parent.mkdir(exist_ok=True)
    with gzip.GzipFile(out, 'wb', mtime=0) as f:
        f.write(json.dumps(dict(inventories=inventories, adapters=adapters, scans=scans, histories=histories), sort_keys=True).encode())
    print(json.dumps(dict(inventories=len(inventories), scans=len(scans), accepted=sum(s['ok'] for s in scans), histories=len(histories),
                          devices=sum(len(i['result']['devices']) for i in inventories), adapters=sum(len(i['result']['adapters']) for i in inventories))))


if __name__ == '__main__':
    main()
