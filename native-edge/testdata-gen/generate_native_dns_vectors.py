"""Generate Go compatibility vectors from gamebond.dns (no sockets).

native-edge/dns must reproduce config accept/reject, DNSResponder.answer() and
override_response() byte for byte over valid, EDNS, truncated and fuzzed queries.
"""
import gzip
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.dns import DNSResponder, load_dns_config, override_response  # noqa: E402


def qname(name):
    return b''.join(bytes([len(x)]) + x.encode() for x in name.split('.') if x) + b'\0'


def query(tx, name, kind=1, cls=1, flags=0x0100, edns=None, extra=b''):
    pkt = struct.pack('!HHHHHH', tx, flags, 1, 0, 0, 1 if edns else 0) + qname(name) + struct.pack('!HH', kind, cls)
    if edns:
        pkt += b'\0' + struct.pack('!HHIH', 41, edns, 0, 0)
    return pkt + extra


LONG = '.'.join(c * 60 for c in 'abc') + '.test'
CONFIGS = [
    dict(records={'Game.Example.com.': {'A': ['10.1.2.3', '10.1.2.4'], 'AAAA': ['fd00::1']}, 'only-a.test': {'A': ['192.0.2.9']}}, ttl=30,
         bind=['127.0.0.1', 0]),
    dict(records={'many.test': {'A': ['10.0.0.%d' % i for i in range(1, 17)]}, LONG: {'AAAA': ['fd00::%x' % i for i in range(1, 17)]}}, bind=['127.0.0.1', 0]),
    dict(records={}, enabled=False, bind=['127.0.0.1', 0]),
]
BAD = [
    dict(records={'a.b': {'A': ['10.0.0.1']}}, bind=['10.9.9.9', 53]), dict(records={'a.b': {'A': ['10.0.0.1']}}, bind=['10.77.0.2', 5353]),
    dict(records={'*.b': {'A': ['10.0.0.1']}}, bind=['127.0.0.1', 0]), dict(records={'a.b': {'A': ['::1']}}, bind=['127.0.0.1', 0]),
    dict(records={'a.b': {'MX': ['10.0.0.1']}}, bind=['127.0.0.1', 0]), dict(records={'a.b': {'A': ['10.0.0.1']}}, ttl=301, bind=['127.0.0.1', 0]),
    dict(records={'a.b': {'A': ['10.0.0.1']}}, workers=9, bind=['127.0.0.1', 0]), dict(records={'a.b': {'A': ['10.0.0.1']}}, timeout=.01, bind=['127.0.0.1', 0]),
    dict(records={'a.b': {'A': ['10.0.0.1']}}, upstream=['10.0.0.1', 53], bind=['127.0.0.1', 0]), dict(records={'a.b': {'A': ['10.0.0.1']}}, bogus=1),
    dict(records={}, bind=['127.0.0.1', 0]), dict(records={'a.b': {'A': ['10.0.0.1']}}, pending=33, bind=['127.0.0.1', 0]),
    dict(records={'a.b': {'A': ['10.0.0.1']}, 'A.B.': {'A': ['10.0.0.2']}}, bind=['127.0.0.1', 0]),
]
GOOD_UPSTREAM = dict(records={'a.b': {'A': ['10.0.0.1']}}, upstream=['8.8.8.8', 53], bind=['127.0.0.1', 0])


def main():
    rng = random.Random(53)
    bad = []
    for raw in BAD:
        try:
            load_dns_config(raw)
            raise SystemExit(f'expected rejection of {raw}')
        except ValueError:
            bad.append(raw)
    load_dns_config(GOOD_UPSTREAM)
    cases = []
    names = [LONG, 'game.example.com', 'GAME.EXAMPLE.COM', 'only-a.test', 'many.test', 'other.example', 'a.b', 'x' * 63 + '.test', 'bad name.test']
    for ci, raw in enumerate(CONFIGS + [GOOD_UPSTREAM]):
        cfg = load_dns_config(raw)
        responder = DNSResponder(cfg)
        packets = []
        for name in names:
            for kind in (1, 28, 15, 255):
                for cls in (1, 3):
                    for edns in (None, 512, 640, 700, 1232, 4096):
                        packets.append(query(rng.randrange(65536), name, kind, cls, edns=edns))
        packets.append(query(1, 'game.example.com', flags=0x8100))              # response bit
        packets.append(query(1, 'game.example.com', flags=0x2100))              # non-standard opcode
        packets.append(query(1, 'game.example.com', extra=b'\0'))               # trailing bytes
        packets.append(query(1, 'game.example.com')[:-3])                       # truncated
        packets.append(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01')   # pointer loop
        packets.append(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x40abc\x00\x00\x01\x00\x01')  # bad label
        for _ in range(400):                                                    # mutated valid packets
            base = bytearray(query(rng.randrange(65536), rng.choice(names), rng.choice((1, 28)), edns=rng.choice((None, 1232))))
            for _ in range(rng.randrange(1, 4)):
                base[rng.randrange(len(base))] = rng.randrange(256)
            if rng.random() < .3:
                base = base[:rng.randrange(1, len(base))]
            packets.append(bytes(base))
        rows = []
        for p in packets:
            if raw.get('upstream') and not (len(p) >= 12):
                continue
            tcp = rng.random() < .3
            if raw.get('upstream'):
                # forwarding needs a network; only record queries that never reach upstream
                try:
                    from gamebond.dns import parse_question
                    q = parse_question(p)
                    if q.cls == 1 and q.name not in cfg.records:
                        continue
                except Exception:
                    pass
            ov = override_response(cfg, p)
            rows.append(dict(packet=p.hex(), tcp=tcp, answer=responder.answer(p, tcp=tcp).hex(), override=ov.hex() if ov is not None else None))
        cases.append(dict(config=raw, rows=rows, stats=responder.stats()))
    out = ROOT / 'native-edge/dns/testdata/dns-vectors.json.gz'
    out.parent.mkdir(exist_ok=True)
    with gzip.GzipFile(out, 'wb', mtime=0) as f:
        f.write(json.dumps(dict(bad=bad, cases=cases), sort_keys=True).encode())
    print(json.dumps(dict(cases=len(cases), rows=sum(len(c['rows']) for c in cases), bad=len(bad))))


if __name__ == '__main__':
    main()
