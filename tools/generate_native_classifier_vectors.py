"""Generate Go compatibility vectors from Python Classifier and mark_game_udp.

Deterministic: seeded RNG and a fake clock, no sockets or network. The Go port
in native-edge/bond (qos.go, packet.go) must reproduce every recorded result.
"""
import gzip
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.policy import Classifier, QueuePolicy, parse_packet  # noqa: E402
from gamebond.userspace import mark_game_udp  # noqa: E402

POLICIES = {46: QueuePolicy(True, True, 40, 128), 34: QueuePolicy(True, False, 80, 256), 8: QueuePolicy(False, False, 300, 512)}
GAME_PORTS = [27015, 3074]


def checksum(header):
    total = sum(struct.unpack('!%dH' % (len(header) // 2), header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build(proto, src, dst, sport, dport, dscp, ecn=0, ident=1, frag=0, more=False, payload=b'x' * 20, tcp_flags=0x10):
    if proto == 17:
        body = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    else:
        body = struct.pack('!HHIIBBHHH', sport, dport, 1, 1, 5 << 4, tcp_flags, 1000, 0, 0) + payload
    flags_frag = (0x2000 if more else 0) | (frag // 8)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, (dscp << 2) | ecn, 20 + len(body), ident, flags_frag, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + body


def main():
    rng = random.Random(7)
    hosts = [bytes([10, 0, 0, i]) for i in range(1, 5)]
    now, rows = 1000.0, []
    clock = [now]
    classifier = Classifier(POLICIES, game_ports=GAME_PORTS, clock=lambda: clock[0])
    for step in range(600):
        clock[0] += rng.choice([0.001, 0.01, 0.5, 30, 130]) if step % 7 == 0 else 0.001
        proto = rng.choice([17, 17, 6])
        a, b = rng.sample(hosts, 2)
        sport = rng.choice([27015, 3074, 40000, 40001, 5000])
        dport = rng.choice([27015, 443, 53, 40000, 40001])
        dscp = rng.choice([0, 0, 0, 46, 34, 8, 12, 63])
        kind = rng.choice(['plain', 'plain', 'plain', 'first_frag', 'later_frag'])
        ident = rng.randrange(1, 4)
        if kind == 'plain':
            packet = build(proto, a, b, sport, dport, dscp, rng.randrange(4), ident)
        elif kind == 'first_frag':
            packet = build(proto, a, b, sport, dport, dscp, 0, ident, 0, True, b'y' * 40)
        else:
            packet = build(proto, a, b, sport, dport, dscp, 0, ident, 8 * rng.randrange(1, 3), rng.random() < .5, b'z' * 16)
        row = dict(step=step, now=clock[0], packet=packet.hex())
        try:
            parse_packet(packet)
            c = classifier.classify(packet)
            row['result'] = dict(tag=c.dscp, reason=c.reason, priority=c.policy.priority, replicate=c.policy.replicate,
                                 max_age_ms=c.policy.max_age_ms, capacity=c.policy.capacity, retransmissions=c.policy.retransmissions)
        except ValueError as exc:
            row['error'] = str(exc)
        try:
            row['marked'] = mark_game_udp(packet, GAME_PORTS).hex()
        except ValueError:
            row['marked'] = None
        rows.append(row)
    # Malformed packets: classification must reject; marking must follow Python.
    for packet in (b'', b'\x45' * 10, build(17, hosts[0], hosts[1], 1, 2, 0)[:-3], bytes([0x65]) + build(17, hosts[0], hosts[1], 1, 2, 0)[1:]):
        row = dict(step=-1, now=clock[0], packet=packet.hex())
        try:
            parse_packet(packet)
            row['result'] = 'unexpected'
        except ValueError as exc:
            row['error'] = str(exc)
        try:
            row['marked'] = mark_game_udp(packet, GAME_PORTS).hex()
        except ValueError:
            row['marked'] = None
        rows.append(row)
    out = ROOT / 'native-edge/bond/testdata/classifier-vectors.json.gz'
    with gzip.open(out, 'wt') as f:
        json.dump(dict(policies={str(k): dict(priority=v.priority, replicate=v.replicate, max_age_ms=v.max_age_ms, capacity=v.capacity, retransmissions=v.retransmissions) for k, v in POLICIES.items()},
                       game_ports=GAME_PORTS, rows=rows), f)
    print(len(rows), 'rows;', sum('result' in r and r['result'] != 'unexpected' for r in rows), 'classified;', sum(r.get('error') is not None for r in rows), 'rejected;',
          sum(r['marked'] is not None and r['marked'] != r['packet'] for r in rows), 'marked')


if __name__ == '__main__':
    main()
