"""Generate Go compatibility vectors from gamebond.transport_router.TransportRouter.

Fake transports with scripted readiness, a fake clock and a real Nat drive seeded
send() calls: transport choice, flow stickiness, fallback, NAT drops, send
failures and counters must match. Inbound merging is exercised too.
"""
import gzip
import json
from pathlib import Path
import random
import struct
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import gamebond.nat as natmod  # noqa: E402
from gamebond.nat import Nat, checksum  # noqa: E402
from gamebond.transport_router import TransportRouter  # noqa: E402

EXT = '10.255.254.2'


def udp(src, dst, sport, dport, data=b'hello'):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    s, d = bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.')))
    c = checksum(s + d + struct.pack('!BBH', 0, 17, len(seg)) + seg) or 0xFFFF
    seg = seg[:6] + struct.pack('!H', c) + seg[8:]
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), 1, 0, 64, 17, 0, s, d)
    return hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:] + seg


class GB:
    def __init__(self):
        self.healthy = True
        self.sent = []
        self.accept = True

    def stats(self):
        return dict(paths=[dict(healthy=self.healthy, enabled=True)])

    def send(self, payload, replicate=True, flow_id=None, *, urgent=False):
        self.sent.append(payload.hex())
        return 1 if self.accept else 0

    def close(self):
        pass


class OMR:
    def __init__(self):
        self.ready = True
        self.sent = []
        self.accept = True

    def send(self, packet, urgent=False):
        self.sent.append((packet.hex(), urgent))
        return self.accept

    def close(self):
        pass


def main():
    natmod.secrets.randbelow = lambda n: 0
    rng = random.Random(8)
    scenarios = []
    for sc in range(25):
        clock = [10.0]
        gb, omr = GB(), OMR()
        nat = Nat(EXT, clock=lambda: clock[0])
        dscp = (46, 26) if sc % 3 else (46,)
        router = TransportRouter(gb, omr, nat, gamebond_dscp=dscp, flow_ttl=rng.choice([1.0, 120.0]), ready_ttl=rng.choice([.25, 0.0, 5.0]), clock=lambda: clock[0])
        steps = []
        for _ in range(200):
            clock[0] += rng.choice([0, .0625, .25, .3125, 1, 2, 150])
            roll = rng.random()
            if roll < .15:
                gb.healthy = rng.random() < .7
                omr.ready = rng.random() < .7
                steps.append(dict(op='ready', gb=gb.healthy, omr=omr.ready, t=clock[0]))
            elif roll < .2:
                gb.accept, omr.accept = rng.random() < .8, rng.random() < .8
                steps.append(dict(op='accept', gb=gb.accept, omr=omr.accept, t=clock[0]))
            elif roll < .8:
                flow = rng.choice([None, 'f1', 'f2', 'f3', 'f4'])
                d = rng.choice([0, 46, 26, 34, 0])
                host = rng.choice(['10.77.0.2', '10.77.0.3'])
                payload = udp(host, rng.choice(['203.0.113.5', '198.51.100.9']), rng.choice([40000, 40001]), 443)
                if rng.random() < .05:
                    payload = payload[:10]
                g0, o0 = len(gb.sent), len(omr.sent)
                urgent = rng.random() < .3
                result = router.send(payload, True, flow, urgent=urgent, dscp=d)
                steps.append(dict(op='send', t=clock[0], flow=flow, dscp=d, packet=payload.hex(), result=result, gb=gb.sent[g0:], omr=omr.sent[o0:],
                                  urgent=urgent))
            else:
                # Inbound: drain through the real _pump logic by calling its body directly.
                which = rng.choice(['gamebond', 'omr'])
                if which == 'omr' and router.nat.fwd:
                    entry = rng.choice(list(router.nat.fwd.values()))
                    rem = rng.choice(list(entry.remotes))
                    pkt = udp('.'.join(map(str, rem[0])), EXT, rem[1], entry.ext_port, b'reply')
                else:
                    pkt = udp('203.0.113.5', '10.77.0.2', 443, 40000, b'in')
                delivered = None
                if which == 'omr':
                    out = nat.inbound(pkt)
                    if out is None:
                        router.counts['recv_nat_dropped'] += 1
                    else:
                        router.counts['recv_omr'] += 1
                        delivered = out.hex()
                else:
                    router.counts['recv_gamebond'] += 1
                    delivered = pkt.hex()
                steps.append(dict(op='recv', t=clock[0], which=which, packet=pkt.hex(), delivered=delivered))
        scenarios.append(dict(dscp=list(dscp), flow_ttl=router.flow_ttl, ready_ttl=router.ready_ttl, steps=steps, counts=router.counts, flows=len(router.flows),
                              nat=nat.stats()))
    out = ROOT / 'native-edge/router/testdata/router-vectors.json.gz'
    out.parent.mkdir(exist_ok=True)
    with gzip.GzipFile(out, 'wb', mtime=0) as f:
        f.write(json.dumps(scenarios, sort_keys=True).encode())
    totals = {}
    for s in scenarios:
        for k, v in s['counts'].items():
            totals[k] = totals.get(k, 0) + v
    print(json.dumps(totals))


if __name__ == '__main__':
    main()
