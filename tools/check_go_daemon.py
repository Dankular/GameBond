"""Go client daemon (cmd/client) against the real Python GB03 server on loopback.

A scripted fake netstack (speaking the real --proxy-stdio framing) stands in
for netstack/, so this exercises: config loading, per-uplink sockets, the stdio
bridge, game-port marking and classification, bonded send to Python, and bonded
receive from Python back into the stack. No adapters, routes, VPS or user
tunnel are touched.

    go -C native-edge build -o ../build/gamebond-native-client.exe ./cmd/client
    python tools/check_go_daemon.py
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

FAKE_STACK = r'''
import json, struct, sys, time
out, inp = sys.stdout.buffer, sys.stdin.buffer
def frame(kind, payload):
    out.write(struct.pack('!BH', kind, len(payload)) + payload); out.flush()
def udp(sport, dport, n):
    body = struct.pack('!I', n) + b'p' * 60
    udp = struct.pack('!HHHH', sport, dport, 8 + len(body), 0) + body
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return ip + udp
frame(2, json.dumps({"socks": "127.0.0.1:1"}).encode())
time.sleep(float(sys.argv[2]))                 # let the uplinks become ready
for n in range(100):
    frame(0, udp(50000, 27015, n))             # game traffic
    frame(0, udp(50000, 443, 1000 + n))        # ordinary UDP
got = 0
while True:                                    # stay alive: the daemon exits when its stack does
    head = inp.read(3)
    if len(head) < 3: break
    kind, size = struct.unpack('!BH', head); body = inp.read(size)
    if kind == 0:
        got += 1
        if got == 50: open(sys.argv[1], 'w').write(json.dumps({"injected": got}))
'''


def main():
    exe = ROOT / 'build' / ('gamebond-native-client.exe' if sys.platform == 'win32' else 'gamebond-native-client')
    key, session = secrets.token_bytes(32), secrets.token_bytes(16)
    server = Node(key, 'server', session, [('127.0.0.1', 0)], bonding_mode=True, probe_interval=.025,
                  path_timeout=.3, initial_rate_mbps=10, max_rate_mbps=100).start()
    process = None
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        host, port = server.addresses[0]
        (tmp / 'key').write_bytes(key)
        (tmp / 'config.json').write_text(json.dumps(dict(session=session.hex(), bind=[['127.0.0.1', 0], ['127.0.0.1', 0]],
                                                         peer=[host, port], mtu=1280, game_udp_ports=[27015],
                                                         bonding_initial_rate_mbps=10, bonding_max_rate_mbps=100)))
        (tmp / 'stack.py').write_text(FAKE_STACK)
        launcher = tmp / ('stack.cmd' if sys.platform == 'win32' else 'stack.sh')
        result = tmp / 'result.json'
        script = f'"{sys.executable}" "{tmp / "stack.py"}" "{result}" 1.5\n' if sys.platform == 'win32' else f'#!/bin/sh\nexec "{sys.executable}" "{tmp / "stack.py"}" "{result}" 1.5\n'
        launcher.write_text(('@echo off\r\n' + script) if sys.platform == 'win32' else script)
        launcher.chmod(0o755)
        try:
            process = subprocess.Popen([str(exe), '-config', str(tmp / 'config.json'), '-key', str(tmp / 'key'), '-netstack', str(launcher), '-status', str(tmp / 'status.json')],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            received = []
            end = time.monotonic() + 15
            while len(received) < 200 and time.monotonic() < end:
                try:
                    received.append(server.recv(.2))
                except Exception:
                    pass
                if len(received) == 0 and time.monotonic() > end - 5 and not any(p['healthy'] for p in server.stats()['paths']):
                    break
            assert len(received) >= 200, f'server got {len(received)}/200 packets; daemon stderr: {process.poll()}'
            game = [p for p in received if struct.unpack('!H', p[22:24])[0] == 27015]
            other = [p for p in received if struct.unpack('!H', p[22:24])[0] == 443]
            assert len(game) == 100 and len(other) == 100, (len(game), len(other))
            assert all(p[1] >> 2 == 46 for p in game), 'game packets were not marked DSCP 46'
            assert all(p[1] >> 2 == 0 for p in other), 'ordinary packets must keep DSCP 0'
            assert len({p[4:6] for p in game}) == 100, 'duplicate or lost game packets'
            for n in range(60):    # Python -> Go -> stack
                reply = bytes([0x45, 0, 0, 40]) + struct.pack('!HHBBH', n, 0, 64, 17, 0) + bytes([10, 0, 0, 2, 10, 0, 0, 1]) + b'\0' * 20
                server.send(reply, replicate=False, flow_id='daemon')
                time.sleep(.01)
            deadline = time.monotonic() + 10
            while not result.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            assert result.exists(), 'fake stack never reported injected packets'
            injected = json.loads(result.read_text())['injected']
            assert injected >= 50, injected
            stats = server.stats()
            assert stats['auth_failures'] == 0
            status = None
            for _ in range(60):    # the daemon rewrites its status once a second
                time.sleep(.1)
                try:
                    status = json.loads((tmp / 'status.json').read_text())
                except (OSError, ValueError):
                    continue
                if status['packets']['outbound'] == 200 and status['packets']['injected'] >= 50:
                    break
            assert status['state'] == 'running' and status['backend'] == 'go' and status['pid'] == process.pid, status
            assert len(status['transport']['paths']) == 2 and all(p['ready'] for p in status['transport']['paths']), status['transport']
            assert status['packets']['outbound'] == 200 and status['packets']['injected'] >= 50, status['packets']
            print(json.dumps(dict(status='ok', server_received=len(received), game_marked=len(game), injected_into_stack=injected,
                                  healthy_paths=sum(p['healthy'] for p in stats['paths']))))
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
