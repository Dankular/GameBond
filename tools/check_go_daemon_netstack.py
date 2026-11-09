"""Go client daemon + the real netstack helper against the Python GB03 server (loopback).

A SOCKS5 CONNECT through the real netstack makes it emit real IPv4/TCP packets;
they must cross the Go daemon's bridge and bonded uplinks and arrive at the
Python server intact. No adapters, routes or VPS are touched.

    python tools/check_go_daemon_netstack.py
"""
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.transport import Node  # noqa: E402


def csum(data):
    if len(data) % 2:
        data += bytes(1)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def syn_ack(syn):
    """Answer a SYN as the far host would, so the stack completes the connect."""
    ihl = (syn[0] & 15) * 4
    sport, dport, seq = struct.unpack('!HHI', syn[ihl:ihl + 8])
    src, dst = syn[16:20], syn[12:16]
    tcp = struct.pack('!HHIIBBHHH', dport, sport, 5000, seq + 1, 5 << 4, 0x12, 4096, 0, 0)
    tcp = tcp[:16] + struct.pack('!H', csum(src + dst + struct.pack('!BBH', 0, 6, len(tcp)) + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + tcp


def main():
    exe = ROOT / 'build/gamebond-native-client.exe'
    stack = ROOT / 'build/gamebond-netstack.exe'
    key, session = secrets.token_bytes(32), secrets.token_bytes(16)
    server = Node(key, 'server', session, [('127.0.0.1', 0)], bonding_mode=True, probe_interval=.025,
                  path_timeout=.3, initial_rate_mbps=10, max_rate_mbps=100).start()
    process = None
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        host, port = server.addresses[0]
        (tmp / 'key').write_bytes(key)
        (tmp / 'config.json').write_text(json.dumps(dict(session=session.hex(), bind=[['127.0.0.1', 0], ['127.0.0.1', 0]],
                                                         peer=[host, port], mtu=1280)))
        try:
            process = subprocess.Popen([str(exe), '-config', str(tmp / 'config.json'), '-key', str(tmp / 'key'), '-netstack', str(stack),
                                        '-status', str(tmp / 'status.json')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            socks = None
            for line in process.stdout:
                record = json.loads(line)
                if record.get('status') == 'stack_ready':
                    socks = record['socks']
                    break
            assert socks, 'netstack never reported its SOCKS address: ' + (process.stderr.read() if process.poll() is not None else '')
            shost, sport = socks.rsplit(':', 1)
            deadline = time.monotonic() + 8      # wait for both uplinks before using the tunnel
            while time.monotonic() < deadline and sum(p['healthy'] for p in server.stats()['paths']) < 2:
                time.sleep(.05)
            sock = socket.create_connection((shost, int(sport)), timeout=5)
            sock.sendall(b'\x05\x01\x00')
            assert sock.recv(2) == b'\x05\x00', 'SOCKS5 method negotiation failed'
            sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('10.77.0.9') + struct.pack('!H', 8080))
            sock.settimeout(.5)
            syns = []
            end = time.monotonic() + 6
            while time.monotonic() < end and not syns:
                try:
                    packet = server.recv(.3)
                except Exception:
                    continue
                if packet[0] >> 4 == 4 and packet[9] == 6 and packet[16:20] == socket.inet_aton('10.77.0.9'):
                    flags = packet[(packet[0] & 15) * 4 + 13]
                    if flags & 2 and not flags & 16:
                        syns.append(packet)
            assert syns, 'no TCP SYN from the real netstack reached the Python server'
            packet = syns[0]
            ihl = (packet[0] & 15) * 4
            assert struct.unpack('!H', packet[ihl + 2:ihl + 4])[0] == 8080
            assert struct.unpack('!H', packet[2:4])[0] == len(packet)
            server.send(syn_ack(packet), replicate=False, flow_id='netstack')
            sock.settimeout(5)
            reply = sock.recv(10)
            assert reply[:2] == bytes([5, 0]), f'SOCKS connect did not complete after the SYN-ACK: {reply!r}'
            sock.close()
            print(json.dumps(dict(status='ok', syn_bytes=len(packet), socks_connect_completed=True, healthy_paths=sum(p['healthy'] for p in server.stats()['paths']))))
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
            server.close()


if __name__ == '__main__':
    main()
