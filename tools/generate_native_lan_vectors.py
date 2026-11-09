"""Generate Go compatibility vectors from gamebond.lan_gateway.LanGateway.

A fake adapter and clock drive seeded ARP / DHCP / IPv4 / DNS / deliver traffic,
including spoofing, foreign MACs, stale-MAC takeover, oversize DF and non-DF
packets, expiring TTLs and MSS clamping. native-edge/lan must emit identical
frames and tunnel packets and end with identical counters.
"""
import gzip
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.dns import load_dns_config, override_response  # noqa: E402
from gamebond.lan_gateway import LanDevice, LanGateway, build_ipv4, build_udp, inet_checksum  # noqa: E402

CLIENT = '10.77.0.2'
ADAPTER = bytes.fromhex('020000000001')
MACS = [bytes.fromhex('0a0000000001'), bytes.fromhex('0a0000000002'), bytes.fromhex('0a0000000003')]
DEV = bytes([10, 77, 0, 9])
GW = bytes([10, 77, 0, 1])
ZERO4 = bytes(4)
BCAST = b'\xff' * 4
DNS_CFG = dict(records={'game.test': {'A': ['10.1.2.3']}}, bind=['127.0.0.1', 0])


class IO:
    mac = ADAPTER

    def __init__(self):
        self.out = []

    def write(self, f):
        self.out.append(f.hex())

    def close(self):
        pass


def eth(dst, src, et, payload):
    return dst + src + struct.pack('!H', et) + payload


def arp(op, smac, sip, tmac, tip):
    return bytes([0, 1, 8, 0, 6, 4]) + struct.pack('!H', op) + smac + sip + tmac + tip


def dhcp(kind, mac, xid=b'\x01\x02\x03\x04', requested=None, server=None, bad=None):
    body = struct.pack('!BBBB4sHH4s4s4s4s', 1, 1, 6, 0, xid, 0, 0x8000, ZERO4, ZERO4, ZERO4, ZERO4) + mac + bytes(10) + bytes(192) + bytes([0x63, 0x82, 0x53, 0x63])
    opts = bytes([53, 1, kind])
    if requested:
        opts += bytes([50, 4]) + requested
    if server:
        opts += bytes([54, 4]) + server
    body += opts + b'\xff'
    if bad == 'magic':
        body = body[:236] + bytes(4) + body[240:]
    if bad == 'short':
        body = body[:100]
    if bad == 'chaddr':
        body = body[:28] + bytes([0xde, 0xad, 0xbe, 0xef, 0, 1]) + body[34:]
    return build_ipv4(ZERO4, BCAST, 17, build_udp(ZERO4, BCAST, 68, 67, body))


def tcp_syn(src, dst, mss, df=False, ttl=64, size=0):
    opts = bytes([2, 4]) + struct.pack('!H', mss) + bytes([1, 1, 4, 2])
    seg = struct.pack('!HHIIBBHHH', 40000, 443, 1, 0, (5 + len(opts) // 4) << 4, 2, 4096, 0, 0) + opts + b'x' * size
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(seg))
    seg = seg[:16] + struct.pack('!H', inet_checksum(pseudo + seg)) + seg[18:]
    return build_ipv4(src, dst, 6, seg, ttl=ttl, flags_frag=0x4000 if df else 0)


def udp_pkt(src, dst, sport, dport, data, ttl=64, df=False):
    return build_ipv4(src, dst, 17, build_udp(src, dst, sport, dport, data), ttl=ttl, flags_frag=0x4000 if df else 0)


def dns_query(name):
    q = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + bytes(1)
    return struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', 1, 1)


def run_scenario(rng, sc):
    pinned = MACS[0] if sc % 3 == 1 else None
    dns_on = sc % 2 == 0
    device = LanDevice('Console', '10.77.0.9', interface_name='eth9', device_mac=':'.join('%02x' % b for b in pinned) if pinned else '',
                       dns=('1.1.1.1', '9.9.9.9') if sc % 4 == 3 else ('1.1.1.1', '8.8.8.8'))
    clock = [500.0]
    io = IO()
    tunnel = []
    cfg = load_dns_config(DNS_CFG)
    gw = LanGateway(device, io, lambda p: tunnel.append(p.hex()), client_tunnel_ip=CLIENT, tunnel_mtu=rng.choice([1280, 1400, 1500]), lease_seconds=rng.choice([86400, 600]),
                    stale_seconds=rng.choice([5, 120]), clock=lambda: clock[0], dns_override=(lambda q: override_response(cfg, q)) if dns_on else None)
    steps = []
    for _ in range(160):
        clock[0] += rng.choice([0, .1, 3, 60, 200])
        mac = rng.choice(MACS)
        r = rng.random()
        kind, data = 'frame', None
        if r < .12:
            data = eth(rng.choice([ADAPTER, BCAST + b'\xff' * 2, ADAPTER, MACS[2]]), mac, 0x0806,
                       arp(rng.choice([1, 1, 2, 3]), rng.choice([mac, mac, MACS[1]]), rng.choice([DEV, DEV, ZERO4, bytes([10, 77, 0, 50])]), bytes(6),
                           rng.choice([GW, DEV, bytes([10, 77, 0, 5]), bytes([10, 77, 0, 255]), bytes([192, 168, 1, 1])])))
        elif r < .3:
            pkt = dhcp(rng.choice([1, 3, 3, 1, 7]), mac, requested=rng.choice([DEV, DEV, bytes([10, 77, 0, 33]), None]), server=rng.choice([None, None, GW, bytes([1, 2, 3, 4])]),
                       bad=rng.choice([None] * 8 + ['magic', 'short', 'chaddr']))
            data = eth(rng.choice([b'\xff' * 6, ADAPTER]), mac, 0x0800, pkt)
        elif r < .75:
            src = rng.choice([DEV, DEV, DEV, bytes([10, 77, 0, 77])])
            dst = rng.choice([bytes([8, 8, 8, 8]), bytes([224, 0, 0, 251]), bytes([10, 77, 0, 255]), DEV, BCAST, bytes([127, 0, 0, 1]), bytes([93, 184, 216, 34])])
            k2 = rng.random()
            if k2 < .3:
                pkt = tcp_syn(src, dst, rng.choice([536, 1460, 1400, 9000]), df=rng.random() < .5, ttl=rng.choice([1, 2, 64]), size=rng.choice([0, 0, 1400]))
            elif k2 < .55:
                pkt = udp_pkt(src, dst, 5353, 53, dns_query(rng.choice(['game.test', 'other.test', 'GAME.test'])), ttl=rng.choice([1, 64]))
            else:
                pkt = udp_pkt(src, dst, 4000, 5000, b'p' * rng.choice([10, 100, 1200, 1400, 2900]), ttl=rng.choice([1, 2, 64]), df=rng.random() < .4)
            if rng.random() < .05:
                pkt = pkt[:rng.randrange(1, 30)]
            if rng.random() < .15:
                pkt = pkt + bytes(rng.randrange(1, 20))
            data = eth(rng.choice([ADAPTER, ADAPTER, b'\xff' * 6]), mac, 0x0800, pkt)
        elif r < .8:
            data = rng.choice([b'short', eth(ADAPTER, ADAPTER, 0x0800, b'x' * 40), eth(ADAPTER, mac, 0x86dd, bytes(40))])
        else:
            kind = 'deliver'
            dst = rng.choice([DEV, DEV, DEV, bytes([10, 77, 0, 8])])
            if rng.random() < .3:
                data = tcp_syn(bytes([8, 8, 8, 8]), dst, rng.choice([1460, 1200]), ttl=rng.choice([1, 64]))
            else:
                data = udp_pkt(bytes([8, 8, 8, 8]), dst, 53, 5353, b'r' * rng.choice([10, 1000, 1480, 1600]), ttl=rng.choice([1, 64]))
        before_out, before_tun = len(io.out), len(tunnel)
        res = None
        if kind == 'frame':
            gw.handle_frame(data)
        else:
            res = gw.deliver(data)
        steps.append(dict(kind=kind, t=clock[0], data=data.hex(), result=res, frames=io.out[before_out:], tunnel=tunnel[before_tun:]))
    return dict(pinned=pinned.hex() if pinned else None, dns=dns_on, dns_servers=list(device.dns), mtu=gw.tunnel_mtu, lease=gw.lease_seconds, stale=gw.stale_seconds,
                steps=steps, counters=gw.counters.snapshot(), leased=gw.leased, device_mac=gw.device_mac.hex() if gw.device_mac else None)


def main():
    rng = random.Random(2024)
    scenarios = [run_scenario(rng, i) for i in range(24)]
    out = ROOT / 'native-edge/lan/testdata/lan-vectors.json.gz'
    out.parent.mkdir(exist_ok=True)
    with gzip.GzipFile(out, 'wb', mtime=0) as f:
        f.write(json.dumps(dict(dns_config=DNS_CFG, scenarios=scenarios), sort_keys=True).encode())
    totals = {}
    for s in scenarios:
        for k, v in s['counters'].items():
            totals[k] = totals.get(k, 0) + v
    print(json.dumps(totals))


if __name__ == '__main__':
    main()
