"""Generate Go compatibility vectors from gamebond.omr_glorytun (the Glorytun "mud" client).

A seeded scripted server drives a real MudClient on a fake clock with its sockets
replaced by recorders. Every outgoing datagram is deterministic (the nonce is the
timestamp, the ephemeral keys come from a patched os.urandom), so Go must produce
the same wire bytes, the same decrypted deliveries and the same per-path state
after every step. A seal/unseal/key-derivation section pins the primitives.
"""
import gzip
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
import time as _time  # noqa: E402

import gamebond.omr_glorytun as g  # noqa: E402
from nacl import bindings as sodium  # noqa: E402

KEY = bytes(range(32))
BASE = 1_700_000_000_000_000
SERVER = ('203.0.113.7', 65001)


class FakeClock:
    def __init__(self):
        self.t = BASE

    def now(self):
        return g.tmask(self.t)


class Recorder:
    def __init__(self, slot, out):
        self.slot, self.out = slot, out

    def sendto(self, wire, remote):
        self.out.append((self.slot, bytes(wire), tuple(remote)))

    def close(self):
        pass


def snapshot(c):
    paths = []
    for p in c.paths:
        paths.append([p.status, p.pref, int(p.demoted), int(p.bad), p.reason, p.mtu_ok, p.mtu_last, p.mtu_probe, p.mtu_min, p.mtu_max, int(p.rtt.setup), p.rtt.val, p.rtt.var,
                      p.tx.total, p.tx.bytes, p.tx.rate, p.tx.loss, p.tx.time, p.rx.total, p.rx.bytes, p.rx.loss, p.rx.time, p.msg.sent, p.msg.time, p.msg.tx_time, p.msg.rx_time,
                      p.msg.tx_bytes, p.msg.rx_bytes, p.msg.tx_total, p.msg.rx_total, p.msg.tx_acc, p.msg.rx_acc, int(p.msg.set), p.data_tx, p.idle,
                      -1.0 if p.base_rtt is None else p.base_rtt, p.bad_since, p.good_since, int(p.enabled), p.rx_max_rate, p.tx_max_rate, p.pref, p.base_pref, p.role])
    return dict(pref=c.pref, rate=c.rate, mtu=c.mtu, window=c.window, window_time=c.window_time, last_recv=c.last_recv_time, errors=dict(c.errors),
                use_next=int(c.kx.use_next), remote=c.kx.remote.hex(), ktime=c.kx.time, paths=paths)


def ip_packet(rng, size):
    body = bytes(i % 251 for i in range(max(0, size - 20)))
    return bytes([0x45, 0]) + size.to_bytes(2, 'big') + bytes(rng.randrange(256) for _ in range(4)) + bytes([64, 17, 0, 0, 10, 255, 254, 2, 8, 8, 8, 8]) + body


def scenario(seed, heavy=False):
    rng = random.Random(seed)
    urandom_log = []
    stream = random.Random(seed + 1000)

    def fake_urandom(n):
        data = bytes(stream.randrange(256) for _ in range(n))
        urandom_log.append(data.hex())
        return data

    g.os.urandom = fake_urandom
    clock = FakeClock()
    _time.monotonic = lambda: clock.t / 1e6
    count = rng.choice([1, 2, 2, 3, 3])
    ips = ['127.0.0.%d' % (i + 1) for i in range(count)]
    roles = [rng.choice(['primary', 'primary', 'secondary', 'backup']) for _ in ips]
    if rng.random() < .2:
        roles[rng.randrange(count)] = 'never'
    prefs = None if rng.random() < .7 else [rng.choice([1, 2, 5, 125]) for _ in ips]
    rate = 100.0 if heavy else rng.choice([1.0, 20.0, 100.0])
    beat = rng.choice([100, 50, 250])
    kwargs = dict(rate_mbps=rate, prefs=prefs, beat_ms=beat, roles=roles, clock=clock, jitter_threshold_ms=rng.choice([8.0, 3.0]),
                  demote_after=rng.choice([0.3, 0.05]), recovery_seconds=rng.choice([3.0, 0.5]))
    c = g.MudClient(KEY, SERVER, ips, **kwargs)
    out = []
    has_sock = []
    for slot, p in enumerate(c.paths):
        has_sock.append(p.sock is not None)
        if p.sock is not None:
            c.selector.unregister(p.sock)
            p.sock.close()
            p.sock = Recorder(slot, out)
    init = dict(ips=ips, roles=roles, prefs=prefs, rate_mbps=rate, beat_ms=beat, jitter=kwargs['jitter_threshold_ms'], demote_after=kwargs['demote_after'],
                recovery=kwargs['recovery_seconds'], enabled=[p.enabled for p in c.paths], has_sock=has_sock, t=clock.t, urandom_base=len(urandom_log))

    srv_secret = bytes(rng.randrange(256) for _ in range(32))
    srv_pk = sodium.crypto_scalarmult_base(srv_secret)
    srv = [dict(cap=rng.choice([1000, 1200, 1472, 1522, 600, 900]), loss=rng.choice([.02, .1, .3] if heavy else [0, 0, .02, .3]), rx_b=0, rx_t=0, tx_b=0, tx_t=0, delay=rng.choice([[1000], [4000, 20000], [20000, 150000], [1000, 150000]]),
                reply=rng.choice([1.0, .9, .5]), keep=rng.random()) for _ in ips]
    pending = []   # (due_t, slot, packet)
    client_pk = [None]
    steps = []
    ops_out = []

    def drain():
        items = []
        while True:
            try:
                items.append(c.inbox.get_nowait().hex())
            except Exception:
                break
        return items

    def record(op, ret=None):
        wires = [[s, w.hex(), list(r)] for s, w, r in out]
        digests = [[s, hashlib.sha256(w).hexdigest(), len(w), list(r)] for s, w, r in out]
        del out[:]
        # Send steps carry only the window; the next tick snapshot validates the accumulated state.
        snap = dict(window=c.window) if op['kind'] == 'send' else snapshot(c)
        steps.append(dict(op=op, ret=ret, out=digests, inbox=[hashlib.sha256(bytes.fromhex(x)).hexdigest() for x in drain()], snap=snap))
        return wires

    def server_react(wires, now):
        for slot, wire_hex, _ in wires:
            wire = bytes.fromhex(wire_hex)
            s = srv[slot]
            if rng.random() >= s['loss']:
                s['rx_b'] += len(wire)
                s['rx_t'] += 1
            header = int.from_bytes(wire[:6], 'little')
            if not header & 1:
                continue
            plain = g.unseal(KEY, wire)
            if plain is None or len(wire) > s['cap'] or rng.random() >= s['reply']:
                continue
            msg = g.Msg.unpack(plain)
            client_pk[0] = msg.pkey
            due = now + rng.choice(s['delay'])
            reply_msg = g.Msg(sent_time=header, aes=0, pkey=srv_pk, tx=(s['tx_b'] + len(wire), s['tx_t'] + 1), rx=(s['tx_b'] + len(wire), s['tx_t'] + 1),
                              fw=(s['rx_b'], s['rx_t']), max_rate=rng.choice([0, 12_500_000]), beat=msg.beat, mtu=msg.mtu, pref=msg.pref,
                              loss=rng.choice([0, 0, 0, 3, 40]), fixed_rate=1, loss_limit=255, addr=('198.51.100.1', 40000 + slot))
            s['tx_b'] += len(wire)
            s['tx_t'] += 1
            body = reply_msg.pack().ljust(len(wire) - g.PKT_MIN, b'\0')
            pending.append((due, slot, g.seal(KEY, g._store(due | 1, 6), body)))

    def derived_key():
        if client_pk[0] is None:
            return None
        shared = sodium.crypto_scalarmult(srv_secret, client_pk[0])
        return g._hash_key(KEY, shared, client_pk[0], srv_pk)

    def do_in(slot, packet, addr=None):
        p = c.paths[slot]
        before = len(out)
        c._on_packet(p, addr or p.remote, packet)
        steps_op = dict(kind='in', slot=slot, addr=list(addr or p.remote), packet=packet.hex(), t=clock.t)
        wires = record(steps_op)
        return wires

    def do_tick():
        c._update()
        wires = record(dict(kind='tick', t=clock.t))
        server_react(wires, clock.t)

    steps_init = dict(kind='start', t=clock.t)
    c.kx.rotate_if_due(clock.now())
    record(steps_init)
    big_jump = rng.random() < .25
    for step in range(rng.choice([150, 200]) if heavy else rng.choice([300, 400, 500])):
        dt = rng.choice([5000, 5000, 5000, 5000, 1000, 20000, 100000])
        if big_jump and step == 200:
            dt = 61 * 60 * 1_000_000
        clock.t += dt
        due = sorted((x for x in pending if x[0] <= clock.t), key=lambda x: x[0])
        for x in due:
            pending.remove(x)
            do_in(x[1], x[2])
            if rng.random() < .05:
                do_in(x[1], x[2])                            # duplicate delivery
        do_tick()
        roll = rng.random()
        if roll < (.8 if heavy else .35):
            for _ in range(rng.choice([40, 80]) if heavy else rng.choice([1, 3, 10])):
                packet = ip_packet(rng, rng.choice([40, 60]) if heavy else rng.choice([40, 100, 576, 1000, 1400, 1500]))
                urgent = rng.random() < .2
                ret = c.send(packet, urgent)
                wires = record(dict(kind='send', packet=packet.hex(), urgent=urgent, t=clock.t), ret)
                server_react(wires, clock.t)
        elif roll < .55:
            slot = rng.randrange(count)
            kind = rng.choice(['data', 'data', 'data', 'garbage', 'tamper', 'short', 'badaddr', 'old', 'tiny', 'badver', 'zero_sent'])
            key = KEY if (derived_key() is None or rng.random() < .4) else derived_key()
            ts = g.tmask(clock.t) - rng.choice([0, 0, 2, 1000])
            if kind == 'data':
                do_in(slot, g.seal(key, g._store(ts, 6), ip_packet(rng, rng.choice([20, 60, 500, 1400]))))
            elif kind == 'garbage':
                do_in(slot, bytes(rng.randrange(256) for _ in range(rng.choice([23, 100, 400]))))
            elif kind == 'tamper':
                pkt = bytearray(g.seal(key, g._store(ts, 6), ip_packet(rng, 100)))
                pkt[rng.randrange(6, len(pkt))] ^= 1
                do_in(slot, bytes(pkt))
            elif kind == 'short':
                do_in(slot, bytes(rng.randrange(256) for _ in range(rng.choice([0, 5, 22]))))
            elif kind == 'badaddr':
                do_in(slot, g.seal(key, g._store(ts, 6), ip_packet(rng, 100)), ('198.51.100.99', 5))
            elif kind == 'old':
                old = g.tmask(clock.t - 11 * 60 * 1_000_000)
                do_in(slot, g.seal(key, g._store(old, 6), ip_packet(rng, 100)))
            elif kind == 'tiny':
                do_in(slot, g.seal(key, g._store(ts, 6), bytes(rng.randrange(256) for _ in range(rng.choice([1, 10, 19])))))
            elif kind == 'badver':
                pkt = bytearray(ip_packet(rng, 100))
                pkt[0] = rng.choice([0x10, 0x30, 0x75, 0x00])
                do_in(slot, g.seal(key, g._store(ts, 6), bytes(pkt)))
            elif kind == 'zero_sent':
                body = g.Msg(sent_time=0, pkey=srv_pk).pack().ljust(200 - g.PKT_MIN, b'\0')
                do_in(slot, g.seal(KEY, g._store(g.tmask(clock.t) | 1, 6), body))
        elif roll < .58:
            new_roles = [rng.choice(['primary', 'secondary', 'backup', 'never']) for _ in ips]
            try:
                c.set_roles(new_roles)
                ret = 'ok'
            except ValueError:
                ret = 'error'
            record(dict(kind='roles', roles=new_roles), ret)
        elif roll < .61:
            up = [rng.choice([0, 0, 5.0, 40.0]) for _ in ips]
            down = [rng.choice([0, 0, 5.0, 40.0]) for _ in ips]
            if rng.random() < .1:
                up[0] = -1
            try:
                c.set_rates(up, down)
                ret = 'ok'
            except ValueError:
                ret = 'error'
            record(dict(kind='rates', up=up, down=down), ret)
    for p in c.paths:
        if p.sock is not None and not isinstance(p.sock, Recorder):
            p.sock.close()
    c.selector.close()
    init['urandom'] = urandom_log
    return dict(init=init, steps=steps, final_stats_keys=sorted(c.errors))


def primitives():
    rng = random.Random(9)
    seals = []
    for _ in range(300):
        key = bytes(rng.randrange(256) for _ in range(32))
        header = g._store(rng.randrange(1 << 47) << 1, 6)
        plain = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 15, 16, 17, 63, 64, 65, 125, 700, 1400])))
        wire = g.seal(key, header, plain)
        bad = bytearray(wire)
        bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
        seals.append(dict(key=key.hex(), plain=plain.hex(), wire=wire.hex(), bad=bytes(bad).hex(), bad_ok=g.unseal(key, bytes(bad)) is not None))
    hashes = []
    for _ in range(100):
        parts = [bytes(rng.randrange(256) for _ in range(32)) for _ in range(4)]
        hashes.append(dict(parts=[x.hex() for x in parts], out=g._hash_key(*parts).hex()))
    msgs = []
    for _ in range(200):
        m = g.Msg(sent_time=rng.randrange(1 << 48), aes=rng.randrange(2), pkey=bytes(rng.randrange(256) for _ in range(32)),
                  tx=(rng.randrange(1 << 62), rng.randrange(1 << 62)), rx=(rng.randrange(1 << 62), rng.randrange(1 << 62)), fw=(rng.randrange(1 << 62), rng.randrange(1 << 62)),
                  max_rate=rng.randrange(1 << 62), beat=rng.randrange(1 << 48), mtu=rng.randrange(1 << 16), pref=rng.randrange(256), loss=rng.randrange(256),
                  fixed_rate=rng.randrange(256), loss_limit=rng.randrange(256), addr=('%d.%d.%d.%d' % tuple(rng.randrange(256) for _ in range(4)), rng.randrange(65536)))
        msgs.append(dict(hex=m.pack().hex(), fields=dict(sent_time=m.sent_time, aes=m.aes, pkey=m.pkey.hex(), tx=list(m.tx), rx=list(m.rx), fw=list(m.fw), max_rate=m.max_rate,
                    beat=m.beat, mtu=m.mtu, pref=m.pref, loss=m.loss, fixed_rate=m.fixed_rate, loss_limit=m.loss_limit, addr=list(m.addr))))
    # Statistics used by the RTT estimator.
    stats = []
    for _ in range(50):
        s = g._Stat()
        values = [rng.randrange(0, 400000) for _ in range(rng.choice([1, 2, 10, 50]))]
        trace = []
        for v in values:
            s.update(v)
            trace.append([s.val, s.var])
        stats.append(dict(values=values, trace=trace))
    # MTU binary search.
    mtus = []
    for _ in range(100):
        p = g.Path('127.0.0.1', None, SERVER, 1, 1)
        ops = []
        trace = []
        for _ in range(rng.choice([5, 20, 40])):
            size = rng.choice([0, 0, rng.randrange(g.MTU_MIN, g.MTU_MAX + 1), p.mtu_probe or 0])
            ops.append(size)
            p.update_mtu(size)
            trace.append([p.mtu_min, p.mtu_max, p.mtu_probe, p.mtu_last])
        mtus.append(dict(ops=ops, trace=trace))
    return dict(seals=seals, hashes=hashes, msgs=msgs, stats=stats, mtus=mtus)


def main():
    scenarios = [scenario(seed) for seed in range(10)] + [scenario(seed, heavy=True) for seed in range(100, 106)]
    dest = ROOT / 'native-edge/omr/testdata/mud-vectors.json.gz'
    with gzip.GzipFile(dest, 'wb', mtime=0) as f:
        f.write(json.dumps(dict(primitives=primitives(), scenarios=scenarios), sort_keys=True).encode())
    kinds = {}
    running = 0
    demoted = 0
    for sc in scenarios:
        for st in sc['steps']:
            kinds[st['op']['kind']] = kinds.get(st['op']['kind'], 0) + 1
            if 'paths' in st['snap']:
                running += any(p[0] == g.RUNNING for p in st['snap']['paths'])
                demoted += any(p[2] for p in st['snap']['paths'])
    errs = {}
    for sc in scenarios:
        last = [st for st in sc['steps'] if 'errors' in st['snap']][-1]
        for k, v in last['snap']['errors'].items():
            errs[k] = errs.get(k, 0) + v
    print(json.dumps(dict(kinds=kinds, steps_with_running_path=running, steps_with_demotion=demoted, final_errors=errs)))


if __name__ == '__main__':
    main()
