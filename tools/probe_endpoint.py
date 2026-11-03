"""Probe an isolated GameBond test server with raw IPv4 ICMP and DNS packets.

This binds a transport session to a peer instance: restart BOTH ends with a fresh
shared session before switching from this probe to the actual game client.
No host routes or TUN devices are created by this probe.
"""
import argparse
import json
from pathlib import Path
import secrets
import socket
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gamebond.transport import Node, OVERHEAD


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ipv4(destination, protocol, payload, dscp=46):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + len(payload),
                         secrets.randbelow(65536), 0x4000, 64, protocol, 0,
                         socket.inet_aton("10.77.0.2"), socket.inet_aton(destination))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config")
    parser.add_argument("--key", required=True)
    parser.add_argument("--current-route", action="store_true", help="single path via current routing for endpoint-only test")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    bind = [("0.0.0.0", 0)] if args.current_route else [tuple(b) for b in config["bind"]]
    indices = None if args.current_route else config.get("interface_indices")
    with Node(Path(args.key).read_bytes(), "client", bytes.fromhex(config["session"]),
              bind, tuple(config["peer"]), mtu=config.get("mtu", 1280) + OVERHEAD,
              interface_indices=indices) as node:
        # Establish authenticated paths before injecting raw packets.
        deadline = time.perf_counter() + 10
        while time.perf_counter() < deadline and not any(p["healthy"] for p in node.stats()["paths"]):
            time.sleep(.05)
        ident = secrets.randbelow(65536)
        icmp = struct.pack("!BBHHH", 8, 0, 0, ident, 1) + b"gamebond-probe"
        icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
        query_id = secrets.randbelow(65536)
        dns = struct.pack("!HHHHHH", query_id, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\0\0\x01\0\x01"
        # IPv4 allows a zero UDP checksum; this is only a non-sensitive DNS probe.
        udp = struct.pack("!HHHH", 49177, 53, len(dns) + 8, 0) + dns
        started = time.perf_counter()
        node.send(ipv4("10.77.0.1", 1, icmp))
        node.send(ipv4("1.1.1.1", 17, udp))
        found = {}
        while time.perf_counter() - started < 10 and len(found) < 2:
            try:
                packet = node.recv(timeout=.25)
            except Exception as exc:
                import queue
                if isinstance(exc, queue.Empty):
                    continue
                raise
            if len(packet) < 28 or packet[0] >> 4 != 4:
                continue
            offset = (packet[0] & 15) * 4
            if packet[9] == 1 and packet[offset] == 0 and packet[offset+4:offset+6] == struct.pack("!H", ident):
                found["tunnel_icmp_echo_ms"] = round((time.perf_counter() - started) * 1000, 3)
            elif packet[9] == 17 and packet[offset:offset+4] == struct.pack("!HH", 53, 49177) and packet[offset+8:offset+10] == struct.pack("!H", query_id):
                found["internet_dns_reply_ms"] = round((time.perf_counter() - started) * 1000, 3)
        print(json.dumps({"scope": "endpoint probe; not a physical interruption or CoD test",
                          "results": found, "transport": node.stats()}, indent=2))
        if len(found) != 2:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
