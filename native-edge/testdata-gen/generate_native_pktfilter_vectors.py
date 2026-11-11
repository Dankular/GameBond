"""Write native-edge/pktfilter/testdata/vectors.json.gz from windows_packet_filter."""
import ctypes
import gzip
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond import windows_packet_filter as w  # noqa: E402

rng = random.Random(77)
constants = {n: getattr(w, n) for n in ('IOCTL_GET_TCPIP_INTERFACES', 'IOCTL_SEND_PACKET_TO_ADAPTER', 'IOCTL_READ_PACKET',
                                       'IOCTL_SET_ADAPTER_MODE', 'IOCTL_FLUSH_ADAPTER_QUEUE', 'IOCTL_SET_EVENT', 'TUNNEL_MODE',
                                       'MAX_FRAME_BUFFER')}
sizes = {'adapter_list': ctypes.sizeof(w.TcpAdapterList), 'buffer': ctypes.sizeof(w.IntermediateBuffer),
         'buffer_data_offset': w.IntermediateBuffer.data.offset, 'device_flags_offset': w.IntermediateBuffer.device_flags.offset,
         'length_offset': w.IntermediateBuffer.length.offset, 'eth_request': ctypes.sizeof(w.EthRequest),
         'adapter_mode': ctypes.sizeof(w.AdapterMode), 'adapter_event': ctypes.sizeof(w.AdapterEvent)}
B = chr(92)
names = [B + 'DEVICE' + B + '{D1729BF1-B1FA-422E-98C9-3089D2BA82ED}', B + 'device' + B + '{846b4ea1-346c-4cd1-aba9-54a90d2896a4}', B + 'DEVICE' + B + 'X', '', 'caf' + chr(233)]
cases = []
for _ in range(200):
    listing = w.TcpAdapterList()
    listing.count = rng.choice([0, 1, 3, 32, 40])
    for i in range(32):
        raw = rng.choice(names).encode('latin-1')[:255]
        if rng.random() < .1:
            raw = bytes(rng.randrange(1, 256) for _ in range(rng.randrange(1, 255)))
        for j, c in enumerate(raw):
            listing.names[i][j] = c
        listing.handles[i] = rng.getrandbits(64)
        listing.mediums[i] = rng.getrandbits(32)
        for j in range(6):
            listing.addresses[i][j] = rng.randrange(256)
        listing.mtus[i] = rng.getrandbits(16)
    rows = w.adapter_rows(listing)
    wanted = rng.choice(['{d1729bf1-b1fa-422e-98c9-3089d2ba82ed}', '{846B4EA1-346C-4CD1-AACC-54A90D2896A4}', 'X', '', '{nope}'])
    hit = w.match_adapter(rows, wanted)
    cases.append({'list': bytes(listing).hex(), 'wanted': wanted,
                  'rows': [{'name': r['name'], 'handle': r['handle'], 'mac': r['mac'].hex(), 'mtu': r['mtu']} for r in rows],
                  'match': None if hit is None else rows.index(hit)})
dest = ROOT / 'native-edge/pktfilter/testdata'
dest.mkdir(parents=True, exist_ok=True)
with gzip.open(dest / 'vectors.json.gz', 'wt', encoding='utf-8') as f:
    json.dump({'constants': constants, 'sizes': sizes, 'cases': cases}, f)
print(len(cases))
