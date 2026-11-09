#!/usr/bin/env python3
"""Handshake and ping test of the Glorytun UDP client against a real glorytun/OpenMPTCProuter server.

  python tools/probe_omr_glorytun.py --server VPS_IP:65001 --key-file glorytun.key --local 192.168.1.20 [--local ...]

The key is the 64-hex-character Glorytun key (GLORYTUN_PASS in /root/openmptcprouter_config.txt on the VPS).
Prints path status as JSON. With --ping it also sends ICMP echo from the router tunnel address (default
10.255.254.2) to the server's (default 10.255.254.1) and reports whether the server answered: that proves
packets pass the full encrypted path in both directions. Needs: pip install 'gamebond[omr]'. Run it on a
machine that is not already connected to this server with the same key (one peer per tunnel).
"""
import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gamebond.omr_glorytun import MudClient, parse_key  # noqa: E402


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def icmp_echo(src: str, dst: str, ident: int, seq: int) -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + b"gamebond-probe"
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, 0, 64, 1, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + body


def is_echo_reply(packet: bytes, ident: int) -> bool:
    header = (packet[0] & 15) * 4
    return packet[9] == 1 and len(packet) >= header + 8 and packet[header] == 0 and struct.unpack("!H", packet[header + 4:header + 6])[0] == ident


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="VPS_IP:PORT (OMR default port 65001)")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--local", action="append", required=True, help="local source address of one uplink; repeat per uplink")
    parser.add_argument("--rate-mbps", type=float, default=100.0)
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--ping", action="store_true")
    parser.add_argument("--tunnel-src", default="10.255.254.2")
    parser.add_argument("--tunnel-dst", default="10.255.254.1")
    args = parser.parse_args()
    host, port = args.server.rsplit(":", 1)
    client = MudClient(parse_key(Path(args.key_file).read_text()), (host, int(port)), args.local, rate_mbps=args.rate_mbps).start()
    result = dict(ready=False, ping_replies=0)
    try:
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and not client.ready:
            time.sleep(0.1)
        result["ready"] = client.ready
        if client.ready and args.ping:
            for seq in range(1, 6):
                client.send(icmp_echo(args.tunnel_src, args.tunnel_dst, 0x6742, seq))
                end = time.monotonic() + 1.0
                while time.monotonic() < end:
                    try:
                        if is_echo_reply(client.recv(timeout=0.1), 0x6742):
                            result["ping_replies"] += 1
                            break
                    except Exception:
                        pass
        result["stats"] = client.stats()
    finally:
        client.close()
    print(json.dumps(result, indent=2))
    return 0 if result["ready"] and (not args.ping or result["ping_replies"]) else 1


if __name__ == "__main__":
    sys.exit(main())
