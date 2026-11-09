"""Write native-edge/bond/testdata/flowprofile_vectors.json.gz from the real
userspace.Runtime.observe_flow_profile and AdaptiveQoS.classify/mark_dscp."""
import gzip
import json
import random
import struct
import sys
import threading
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.adaptive_qos import AdaptiveQoS, QoSSettings, mark_dscp  # noqa: E402
from gamebond.policy import Classifier  # noqa: E402
from gamebond.userspace import Runtime  # noqa: E402

rng = random.Random(4242)
CLIENT = '10.20.0.2'


class Fake:
    config = {'client_tunnel_ip': CLIENT}

    def __init__(self):
        self.classify_lock = threading.Lock()
        self.flow_profiles = OrderedDict()


def packet(proto, src, sport, dst, dport, dscp, ecn=0):
    payload = b'x' * rng.randrange(0, 20)
    if proto == 17:
        l4 = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    else:
        l4 = struct.pack('!HHIIBBHHH', sport, dport, 1, 2, 5 << 4, 0x10, 1000, 0, 0) + payload
    head = struct.pack('!BBHHHBBH4s4s', 0x45, dscp << 2 | ecn, 20 + len(l4), 1, 0, 64, proto, 0,
                       bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    s = sum(struct.unpack('!10H', head))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return head[:10] + struct.pack('!H', ~s & 0xFFFF) + head[12:] + l4


def key_hex(key):
    version, proto, a, b = key
    return bytes([proto]).hex() + a[0].hex() + a[1].to_bytes(2, 'big').hex() + b[0].hex() + b[1].to_bytes(2, 'big').hex()


def endpoint():
    return rng.choice([f'{CLIENT}:{rng.randrange(1, 65536)}', f'10.20.0.9:{rng.choice([0, 1, 65535, 65536, 80])}', '1.2.3.4:443',
                       '1.2.3.4', '[::1]:80', 'x:80', f'{CLIENT}: 80', f'{CLIENT}:+80', f'{CLIENT}:8_0', f'{CLIENT}:8__0',
                       f'{CLIENT}:٨٠', 5, None, '2001:db8::1:443'])


observe = []
for _ in range(1500):
    rec = {'type': 'app_flow_profile',
           'profile': rng.choice(['automatic', 'bulk', 'game', 'call', 'stream', 'x', None, 5]),
           'protocol': rng.choice(['tcp', 'udp', 'tcp', 'udp', 'icmp', None]),
           'source': f'{CLIENT}:{rng.randrange(1, 65536)}' if rng.random() < .7 else endpoint(),
           'destination': endpoint()}
    fake = Fake()
    try:
        Runtime.observe_flow_profile(fake, rec)
    except AttributeError:
        pass  # non-string endpoint: Python raises (crashing its reader); Go rejects the record
    out = None
    if fake.flow_profiles:
        (k, v), = fake.flow_profiles.items()
        out = {'key': key_hex(k), 'profile': v['profile']}
    observe.append({'record': rec, 'out': out})

classify = []
for tag in (None, 'enabled', 'disabled'):
    pass
for enabled in (True, False):
    qos = AdaptiveQoS(QoSSettings(enabled=enabled))
    # userspace.py: profile policies only when adaptive QoS is on
    classifier = Classifier(dict(qos.policies) if enabled else {})
    if enabled:
        classifier.policies.pop(0, None)
    for _ in range(600):
        proto = rng.choice([6, 17])
        dscp = rng.choice([0, 0, 8, 18, 26, 46, 34])
        pkt = packet(proto, CLIENT, rng.randrange(1000, 60000), '1.2.3.4', rng.choice([53, 443, 3074, 27015]), dscp, rng.randrange(4))
        profile = rng.choice([None, 'automatic', 'bulk', 'game', 'call', 'stream'])
        classifier.flows.clear() if hasattr(classifier, 'flows') else None
        c = classifier.classify(pkt)
        c2 = qos.classify(c, profile)
        out = pkt
        if profile and qos.settings.enabled:
            out = mark_dscp(pkt, c2.dscp)
        p = c2.policy
        classify.append({'enabled': enabled, 'packet': pkt.hex(), 'profile': profile, 'tag': c2.dscp, 'reason': c2.reason,
                         'policy': [p.priority, p.replicate, p.max_age_ms, p.capacity], 'marked': out.hex()})

dest = ROOT / 'native-edge/bond/testdata'
dest.mkdir(parents=True, exist_ok=True)
with gzip.open(dest / 'flowprofile_vectors.json.gz', 'wt', encoding='utf-8') as f:
    json.dump({'client': CLIENT, 'observe': observe, 'classify': classify}, f, ensure_ascii=False)
print(sum(1 for o in observe if o['out']), len(observe), len(classify))
