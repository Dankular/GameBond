"""Bounded, passive IPv4/UDP timing observer in the GameBond network namespace.

Run with host Python through nsenter -n. Never reads keys or saves payloads.
AF_PACKET observes copies; it does not consume the TUN reader's packets.
"""
import collections
import json
import select
import socket
import struct
import sys
import time

duration = min(900, max(1, int(sys.argv[1]) if len(sys.argv) > 1 else 30))
sockets = {}
for interface in ("eth0", "gamebond0"):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    sock.bind((interface, 0))
    sock.setblocking(False)
    sockets[sock] = interface
started = time.monotonic()
next_report = started + 10
flows = {}
seen = {"up": collections.OrderedDict(), "down": collections.OrderedDict()}
highest = {"up": -1, "down": -1}
outer = {d: dict(copies=0, unique=0, duplicates=0, out_of_order=0, max_gap_ms=0) for d in seen}
last_outer = {}

def report():
    print(json.dumps({"elapsed_s": round(time.monotonic()-started, 1),
        "outer_priority": outer, "game_flows": list(flows.values())}), flush=True)

try:
    while time.monotonic() - started < duration:
        ready, _, _ = select.select(list(sockets), [], [], .2)
        for sock in ready:
            for _ in range(128):
                try:
                    packet, _ = sock.recvfrom(65535)
                except BlockingIOError:
                    break
                now = time.monotonic()
                if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != 17:
                    continue
                ihl = (packet[0] & 15)*4
                if ihl < 20 or len(packet) < ihl+8 or int.from_bytes(packet[6:8], 'big') & 0x3fff:
                    continue
                sport, dport = struct.unpack_from('!HH', packet, ihl)
                source, destination = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
                if sockets[sock] == "gamebond0":
                    if 3075 not in (sport, dport):
                        continue
                    direction = "up" if source == "10.77.0.2" else "down"
                    key = (source, sport, destination, dport)
                    if key not in flows:
                        if len(flows) >= 128:
                            continue
                        flows[key] = dict(direction=direction, source=[source,sport], destination=[destination,dport],
                            packets=0, dscp={}, max_gap_ms=0, gaps_over_50ms=0, last_at=None)
                    flow = flows[key]
                    if flow['last_at'] is not None:
                        gap = (now-flow['last_at'])*1000
                        flow['max_gap_ms'] = max(flow['max_gap_ms'],round(gap,2))
                        flow['gaps_over_50ms'] += gap > 50
                    flow['last_at'] = now
                    flow['packets'] += 1
                    tag = str(packet[1] >> 2)
                    flow['dscp'][tag] = flow['dscp'].get(tag,0)+1
                elif 4433 in (sport,dport):
                    payload = packet[ihl+8:]
                    if len(payload) < 45 or payload[:4] != b'GB03' or payload[36] != 1:
                        continue
                    direction = 'up' if dport == 4433 else 'down'
                    # Include sender prefix to avoid confusing process restarts.
                    identity = (payload[20:36],int.from_bytes(payload[37:45],'big'))
                    stats = outer[direction]
                    stats['copies'] += 1
                    if identity in seen[direction]:
                        stats['duplicates'] += 1
                        continue
                    seen[direction][identity] = None
                    if len(seen[direction]) > 65536:
                        seen[direction].popitem(last=False)
                    stats['unique'] += 1
                    number = identity[1]
                    stats['out_of_order'] += number < highest[direction]
                    highest[direction] = max(highest[direction], number)
                    if direction in last_outer:
                        stats['max_gap_ms'] = max(stats['max_gap_ms'],round((now-last_outer[direction])*1000,2))
                    last_outer[direction] = now
        if time.monotonic() >= next_report:
            report()
            next_report = time.monotonic()+10
finally:
    report()
    for sock in sockets:
        sock.close()
