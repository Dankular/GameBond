"""Generate Go compatibility vectors from gamebond.nat.Nat.

Seeded random outbound/inbound traffic on a fake clock, with scripted port
allocation (secrets.randbelow is replaced by a recorded sequence the Go test
replays). native-edge/nat must produce identical packets and counters.
"""
import gzip
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import gamebond.nat as natmod  # noqa: E402
from gamebond.nat import Nat, checksum  # noqa: E402

EXT = '10.255.254.2'
HOSTS = ['10.77.0.2', '10.77.0.3', '10.77.0.4']
REMOTES = ['203.0.113.5', '198.51.100.7', '192.0.2.44']


def ip_packet(src, dst, proto, payload, flags_frag=0, ihl_opts=b''):
    ihl = 5 + len(ihl_opts) // 4
    hdr = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, ihl * 4 + len(payload), 7, flags_frag, 64, proto, 0, bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.')))) + ihl_opts
    hdr = hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:]
    return hdr + payload


def pseudo(src, dst, proto, seg):
    return bytes(map(int, src.split('.'))) + bytes(map(int, dst.split('.'))) + struct.pack('!BBH', 0, proto, len(seg))


def tcp(src, dst, sport, dport, flags, data=b''):
    seg = struct.pack('!HHIIBBHHH', sport, dport, 1, 2, 5 << 4, flags, 4096, 0, 0) + data
    seg = seg[:16] + struct.pack('!H', checksum(pseudo(src, dst, 6, seg) + seg)) + seg[18:]
    return ip_packet(src, dst, 6, seg)


def udp(src, dst, sport, dport, data=b'hello', nocsum=False):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    if not nocsum:
        c = checksum(pseudo(src, dst, 17, seg) + seg)
        seg = seg[:6] + struct.pack('!H', c or 0xFFFF) + seg[8:]
    return ip_packet(src, dst, 17, seg)


def icmp_echo(src, dst, ident, reply=False):
    body = struct.pack('!BBHHH', 0 if reply else 8, 0, 0, ident, 1) + b'abcd'
    body = body[:2] + struct.pack('!H', checksum(body)) + body[4:]
    return ip_packet(src, dst, 1, body)


def icmp_error(src, dst, quoted, kind=3):
    body = struct.pack('!BBHI', kind, 1, 0, 0) + quoted[:28]
    body = body[:2] + struct.pack('!H', checksum(body)) + body[4:]
    return ip_packet(src, dst, 1, body)


def main():
    rng = random.Random(99)
    scenarios = []
    for sc in range(30):
        fake = [100.0]
        draws, script = [], [rng.randrange(1 << 30) for _ in range(500)]
        pos = [0]
        record = []

        def randbelow(n):
            v = script[pos[0]] % n
            pos[0] += 1
            record.append(v)
            return v

        natmod.secrets.randbelow = randbelow
        kw = dict(max_entries=rng.choice([3, 8, 32768]), port_range=(20000, 20000 + rng.choice([3, 60, 40000])))
        nat = Nat(EXT, clock=lambda: fake[0], **kw)
        sent = []     # (host, hport, proto, remote, rport, ext) for realistic inbound replies
        steps = []
        for _ in range(250):
            fake[0] += rng.choice([0, .01, 1.5, 40, 200, 8000])
            roll = rng.random()
            host, remote = rng.choice(HOSTS), rng.choice(REMOTES)
            sport = rng.choice([40000, 40001, 5000, 500, 1023, 1024, 65535, rng.randrange(1, 65535)])
            dport = rng.choice([53, 443, 27015, 40000])
            if roll < .3:
                pkt, d = udp(host, remote, sport, dport, nocsum=rng.random() < .1), 'out'
            elif roll < .45:
                pkt, d = tcp(host, remote, sport, dport, rng.choice([0x02, 0x10, 0x18, 0x11, 0x04])), 'out'
            elif roll < .5:
                pkt, d = icmp_echo(host, remote, rng.choice([1, 77, 65535])), 'out'
            elif roll < .55:
                pkt, d = ip_packet(host, remote, rng.choice([47, 1]), b'\x03\0\0\0\0\0\0\0'), 'out'
            elif roll < .58:
                pkt, d = udp(host, remote, sport, dport)[:rng.randrange(0, 40)], 'out'
            elif roll < .6:
                pkt, d = ip_packet(host, remote, 17, b'12345678', flags_frag=rng.choice([0x2000, 0x0005])), 'out'
            else:
                d = 'in'
                live = list(nat.fwd.values())
                if live and rng.random() < .85:
                    e = rng.choice(live)
                    ext_port = e.ext_port
                    rem = rng.choice(list(e.remotes) or [(bytes(4), 0)])
                    rip = '.'.join(map(str, rem[0])) if rem[0] != bytes(4) else remote
                    rport = rem[1] if rng.random() < .85 else rng.randrange(1, 65535)
                    kind = rng.random()
                    if e.proto == 17:
                        pkt = udp(rip, EXT, rport, ext_port)
                    elif e.proto == 6:
                        pkt = tcp(rip, EXT, rport, ext_port, rng.choice([0x10, 0x11, 0x04]))
                    else:
                        pkt = icmp_echo(rip, EXT, ext_port, reply=True)
                    if kind < .15 and e.proto in (6, 17):
                        quoted = (udp if e.proto == 17 else lambda *a: tcp(*a, 0x10))(EXT, rip, ext_port, rport)
                        pkt = icmp_error('192.0.2.1', EXT, quoted, rng.choice([3, 4, 11, 12]))
                    elif kind < .2:
                        pkt = udp(rip, '10.9.9.9', rport, ext_port)
                else:
                    pkt = udp(remote, EXT, dport, sport)
            before = len(record)
            out = nat.outbound(pkt) if d == 'out' else nat.inbound(pkt)
            steps.append(dict(dir=d, t=fake[0], packet=pkt.hex(), out=out.hex() if out else None, draws=record[before:]))
        scenarios.append(dict(max_entries=kw['max_entries'], low=kw['port_range'][0], high=kw['port_range'][1], steps=steps, stats=nat.stats()))
    # One mapping contacting more than MAX_REMOTES peers: the oldest must be forgotten.
    fake = [100.0]
    pos = [0]
    record = []
    natmod.secrets.randbelow = lambda n: 0
    nat = Nat(EXT, clock=lambda: fake[0])
    steps = []
    def step(d, pkt):
        out = nat.outbound(pkt) if d == 'out' else nat.inbound(pkt)
        steps.append(dict(dir=d, t=fake[0], packet=pkt.hex(), out=out.hex() if out else None, draws=[]))
    for i in range(140):
        step('out', udp('10.77.0.2', '198.51.100.%d' % (i % 250 + 1), 40000, 9000 + i))
    for i in (0, 11, 12, 13, 139):
        step('in', udp('198.51.100.%d' % (i % 250 + 1), EXT, 9000 + i, 40000))
    scenarios.append(dict(max_entries=32768, low=20000, high=60999, steps=steps, stats=nat.stats()))
    out = ROOT / 'native-edge/nat/testdata/nat-vectors.json.gz'
    out.parent.mkdir(exist_ok=True)
    with gzip.GzipFile(out, 'wb', mtime=0) as f:
        f.write(json.dumps(scenarios, sort_keys=True).encode())
    total = {}
    for s in scenarios:
        for k, v in s['stats'].items():
            total[k] = total.get(k, 0) + v
    print(json.dumps(dict(steps=sum(len(s['steps']) for s in scenarios), totals=total)))


if __name__ == '__main__':
    main()
