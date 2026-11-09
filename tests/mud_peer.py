"""Passive Glorytun UDP ("mud") server for tests, written from the same reading of mud.c as the client.

It proves the client matches that reading. It is NOT independent evidence of interoperability with the
real glorytun binary; see docs/omr-client.md.
"""
import queue
import socket
import struct
import threading
import time

from gamebond.omr_glorytun import (Clock, KeyExchange, MSG_SIZE, Msg, PKT_MAX, PKT_MIN, TIME_SIZE, TIME_TOLERANCE, _load,
                                   _store, seal, tmask, unseal)


class MudPeer:
    def __init__(self, key, clock=None, mtu_limit=PKT_MAX):
        self.clock = clock or Clock()
        self.kx = KeyExchange(key)
        self.kx.rotate_if_due(self.clock.now())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.address = self.sock.getsockname()
        self.mtu_limit = mtu_limit            # largest wire packet the "network" carries
        self.paths = {}                       # remote address -> dict
        self.inbox = queue.Queue()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.errors = dict(decrypt=0, clocksync=0)
        self.blocked = set()                  # source IPs whose packets are silently dropped (a dead link)
        self.delays = {}                      # source IP -> seconds added to everything sent back (a slow link)
        self.arrivals = {}                    # source IP -> data packets received from it
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self._turn = 0

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.sock.close()

    def _run(self):
        while not self.stop.is_set():
            try:
                packet, remote = self.sock.recvfrom(PKT_MAX)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(packet) > self.mtu_limit or len(packet) <= PKT_MIN or remote[0] in self.blocked:
                continue
            with self.lock:
                self._on_packet(packet, remote)

    def _on_packet(self, packet, remote):
        now = self.clock.now()
        header = _load(packet[:TIME_SIZE])
        if tmask(now - header) > TIME_TOLERANCE and tmask(header - now) > TIME_TOLERANCE:
            self.errors["clocksync"] += 1
            return
        is_msg = bool(header & 1)
        plain = unseal(self.kx.private[1], packet) if is_msg else self.kx.decrypt(packet)
        if plain is None:
            self.errors["decrypt"] += 1
            return
        path = self.paths.setdefault(remote, dict(mtu_last=0, rx_bytes=0, rx_total=0, tx_bytes=0, tx_total=0, beat=0,
                                                  max_rate=0, pref=0, fixed_rate=0, loss_limit=0, seen=0.0, sent_data=0))
        path["seen"] = time.monotonic()
        if is_msg:
            msg = Msg.unpack(plain)
            if not msg.sent_time:                     # a probe: copy the initiator's parameters, then echo
                path.update(beat=msg.beat, max_rate=msg.max_rate, pref=msg.pref, fixed_rate=msg.fixed_rate,
                            loss_limit=msg.loss_limit, mtu_last=msg.mtu)
                if msg.pkey != self.kx.remote:
                    self.kx.derive(msg.pkey)
                echo = Msg(sent_time=header, aes=0, pkey=self.kx.local, tx=(path["tx_bytes"], path["tx_total"]),
                           rx=(path["rx_bytes"], path["rx_total"]), fw=msg.tx, max_rate=0, beat=0, mtu=path["mtu_last"],
                           addr=remote)
                body = echo.pack().ljust(len(packet) - PKT_MIN, b"\0")
                self._tx(path, remote, seal(self.kx.private[0], _store(now | 1, TIME_SIZE), body))
        else:
            self.arrivals[remote[0]] = self.arrivals.get(remote[0], 0) + 1
            self.inbox.put(plain)
        path["rx_total"] += 1
        path["rx_bytes"] += len(packet)

    def _tx(self, path, remote, wire):
        path["tx_total"] += 1
        path["tx_bytes"] += len(wire)
        delay = self.delays.get(remote[0], 0)
        if delay:
            def late():
                try:
                    self.sock.sendto(wire, remote)
                except OSError:
                    pass                      # the peer was closed while a delayed packet was pending
            threading.Timer(delay, late).start()
        else:
            self.sock.sendto(wire, remote)

    def usable_remotes(self):
        """What the real server does: only paths with the lowest advertised preference among those still heard from."""
        newest = max((p["seen"] for p in self.paths.values()), default=0.0)
        fresh = [(r, p) for r, p in self.paths.items()
                 if p["mtu_last"] and newest - p["seen"] <= max(5 * p["beat"] / 1e6, 0.1)]
        if not fresh:
            return []
        lowest = min(p["pref"] for _, p in fresh)
        return [r for r, p in fresh if p["pref"] == lowest]

    def send(self, packet):
        """Send one IP packet downstream on the preferred paths, round robin."""
        with self.lock:
            remotes = self.usable_remotes()
            if not remotes:
                return False
            remote = remotes[self._turn % len(remotes)]
            self._turn += 1
            self.paths[remote]["sent_data"] += 1
            self._tx(self.paths[remote], remote, self.kx.encrypt(self.clock.now(), packet))
            return True
