"""Accept/reject vectors for lan_devices validation (gamebond.lan_gateway.load_lan_devices)."""
import gzip
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.lan_gateway import load_lan_devices  # noqa: E402

G1, G2 = '{12345678-1234-1234-1234-123456789abc}', '{AAAAAAAA-1234-1234-1234-123456789abc}'
BASE = dict(name='Console', tunnel_ip='10.77.0.9', interface_name='eth1')
CASES = [
    [], [BASE], [dict(BASE, dns=['1.1.1.1'])], [dict(BASE, dns=[])], [dict(BASE, dns=['127.0.0.1'])], [dict(BASE, dns=['224.0.0.1'])], [dict(BASE, dns=['1.1.1.1'] * 4)],
    [dict(BASE, tunnel_ip='10.77.0.1')], [dict(BASE, tunnel_ip='10.77.0.2')], [dict(BASE, tunnel_ip='10.77.0.255')], [dict(BASE, tunnel_ip='10.77.1.9')], [dict(BASE, tunnel_ip='10.77.0.0')],
    [dict(BASE, name='')], [dict(BASE, name='x' * 33)], [dict(BASE, name='bad/name')], [dict(name='a', tunnel_ip='10.77.0.9')],
    [dict(name='a', tunnel_ip='10.77.0.9', interface_id=G1)], [dict(name='a', tunnel_ip='10.77.0.9', interface_id='nope')], [dict(BASE, interface_name='averyveryverylongname')],
    [dict(BASE, device_mac='aa:bb:cc:dd:ee:ff')], [dict(BASE, device_mac='AA-BB-CC-DD-EE-FF')], [dict(BASE, device_mac='aa:bb')], [dict(BASE, bogus=1)], [dict(BASE, interface_index=-1)],
    [BASE, dict(BASE, tunnel_ip='10.77.0.10')], [BASE, dict(BASE, name='console', interface_name='eth2', tunnel_ip='10.77.0.10')],
    [BASE, dict(BASE, name='B', interface_name='eth2')], [BASE, dict(BASE, name='B', interface_name='ETH1', tunnel_ip='10.77.0.10')],
    [dict(BASE, device_mac='aa:bb:cc:dd:ee:ff'), dict(name='B', tunnel_ip='10.77.0.10', interface_name='eth2', device_mac='AA:BB:CC:DD:EE:FF')],
    [dict(BASE, device_mac='aa:bb:cc:dd:ee:ff'), dict(name='B', tunnel_ip='10.77.0.10', interface_name='eth2', device_mac='aa-bb-cc-dd-ee-ff')],
    [dict(name='a', tunnel_ip='10.77.0.9', interface_id=G1), dict(name='b', tunnel_ip='10.77.0.10', interface_id=G1.upper())],
    [dict(name='a', tunnel_ip='10.77.0.9', interface_id=G2, interface_index=7)], [dict(name='a', tunnel_ip='10.77.0.9', interface_name='e', interface_index=7)],
    [dict(BASE, tunnel_ip='10.77.0.%d' % (9 + i), name='n%d' % i, interface_name='e%d' % i) for i in range(5)],
    [dict(BASE, tunnel_ip='10.77.0.%d' % (9 + i), name='n%d' % i, interface_name='e%d' % i) for i in range(4)],
]
UPLINKS = [dict(interface_ids=[], interface_indices=[]), dict(interface_ids=[G1.upper()], interface_indices=[7]), dict(interface_ids=[G2], interface_indices=[])]


def main():
    rows = []
    for devices in CASES:
        for up in UPLINKS:
            cfg = dict(role='client', client_tunnel_ip='10.77.0.2', lan_devices=devices, **up)
            try:
                got = load_lan_devices(cfg)
                rows.append(dict(devices=devices, uplinks=up, ok=True, count=len(got), identities=[d.identity for d in got], dns=[list(d.dns) for d in got]))
            except (ValueError, TypeError) as exc:
                rows.append(dict(devices=devices, uplinks=up, ok=False))
    out = ROOT / 'native-edge/lan/testdata/lan-config-vectors.json.gz'
    with gzip.GzipFile(out, 'wb', mtime=0) as f:
        f.write(json.dumps(rows, sort_keys=True).encode())
    print(json.dumps(dict(rows=len(rows), accepted=sum(r['ok'] for r in rows))))


if __name__ == '__main__':
    main()
