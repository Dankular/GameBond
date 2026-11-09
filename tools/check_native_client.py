"""Go client role against the real Python GB03 server, over loopback UDP.

The reverse of check_native_receiver.py: a Python ``Node`` runs as the server
and the Go ``client-probe`` (one UDP socket per simulated uplink) is the client.
No capture, routes, adapters, VPS processes or active user tunnel are touched.
This verifies handshake, probing, bonded send and bonded receive between the two
implementations, not physical aggregation.

    go -C native-edge build -o ../build/gamebond-native-client-probe.exe ./cmd/client-probe
    python tools/check_native_client.py [--paths N]
"""
import argparse
import json
from pathlib import Path
import queue
import secrets
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.transport import Node  # noqa: E402

SEND = 200      # Go -> Python payloads
RETURN = 200    # Python -> Go payloads


def payload(n):
    return struct.pack('!Q', n) + bytes([n % 251]) * 992


def wait(predicate, seconds=8, what='condition'):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError(f'Timed out waiting for {what}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--paths', type=int, choices=range(1, 9), default=2)
    parser.add_argument('--mtu', action='store_true', help='enable path MTU discovery on both sides')
    parser.add_argument('--send', type=int, default=200, help='Go -> Python payload count (max 1000)')
    parser.add_argument('--policy', action='store_true', help='Go client sends a primary link policy per uplink')
    parser.add_argument('--no-evidence', action='store_true')
    args = parser.parse_args()
    exe = ROOT / 'build' / ('gamebond-native-client-probe.exe' if sys.platform == 'win32' else 'gamebond-native-client-probe')
    SEND = args.send
    key, session = secrets.token_bytes(32), secrets.token_bytes(16)
    server = Node(key, 'server', session, [('127.0.0.1', 0)], bonding_mode=True, probe_interval=.025,
                  path_timeout=.3, initial_rate_mbps=10, max_rate_mbps=10, path_mtu_discovery=args.mtu).start()
    process = None
    try:
        host, port = server.addresses[0]
        process = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        process.stdin.write(json.dumps(dict(key=key.hex(), session=session.hex(), server=f'{host}:{port}',
                                            paths=args.paths, send=SEND, mtu=args.mtu, policy=args.policy)) + '\n')
        process.stdin.flush()
        assert json.loads(process.stdout.readline())['status'] == 'started'

        wait(lambda: len([p for p in server.stats()['paths'] if p['healthy']]) == args.paths,
             what='every Go uplink to become a healthy server path')
        received, errors = [], []

        def drain():
            while len(received) < SEND:
                try:
                    received.append(server.recv(5))
                except queue.Empty:
                    errors.append('server receive timed out')
                    return
        thread = threading.Thread(target=drain, daemon=True)
        started = time.monotonic()
        thread.start()
        # Python -> Go in small batches, below the Go client's bounded inbox.
        for batch in range(RETURN // 20):
            for n in range(batch * 20, (batch + 1) * 20):
                assert server.send(payload(n), replicate=False, flow_id='native-client') == 1
            time.sleep(.05)
        thread.join(15)
        elapsed = time.monotonic() - started
        assert not errors, errors
        assert len(received) == SEND == len(set(received)), (len(received), len(set(received)))
        assert set(received) == {payload(n) for n in range(SEND)}, 'payload corruption or loss Go -> Python'
        wait(lambda: all(p['bonding']['sent_packets'] > 0 for p in server.stats()['paths']), what='bulk on every path')
        stats = server.stats()
        assert stats['auth_failures'] == 0, stats['auth_failures']

        process.stdin.write('x')
        process.stdin.flush()
        report = json.loads(process.stdout.readline())
        assert process.wait(5) == 0
        assert report['ready_paths'] == args.paths and report['corrupt'] == 0
        assert report['delivered_unique'] == RETURN, report['delivered_unique']
        assert report['sent_enqueued'] and report['transmit_queue']['Expired'] == 0
        assert report['sender']['StripedPackets'] >= SEND
        assert all(p['Budget']['sent_packets'] > 0 for p in report['paths']), 'a Go uplink carried no bulk'
        if args.policy:
            assert all(p['link_policy'] and p['link_policy']['role'] == 'primary' and p['link_policy']['upload_mbps'] == 50 for p in stats['paths']), stats['paths']
            assert all(p['Policy'] and p['PolicyConfirmed'] for p in report['paths']), 'Go uplink never saw the policy confirmed'
        if args.mtu:
            assert stats.get('mtu_acks', 0) >= 0
            assert all(p['mtu'] and p['mtu']['acks'] > 0 for p in stats['paths']), 'Python never got an MTU ack from a Go uplink'
            assert all(p['MTU'] and p['MTUAcks'] > 0 for p in report['paths']), 'Go never got an MTU ack from the Python server'
        evidence = dict(
            scope='Real UDP loopback; Go client role to the Python server; no TUN/VPS/physical aggregation claim',
            uplinks=args.paths, go_to_python_payloads=SEND, python_to_go_payloads=RETURN,
            python_server_paths=[dict(healthy=p['healthy'], sent=p['bonding']['sent_packets']) for p in stats['paths']],
            python_auth_failures=stats['auth_failures'], go=report)
        print(json.dumps(dict(mtu=args.mtu, uplinks=args.paths, send=SEND, python_receive_seconds=round(elapsed, 3), mbit_per_s=round(SEND * 1000 * 8 / elapsed / 1e6, 2))))
        if args.no_evidence:
            return
        target = ROOT / 'evidence' / ('native-client-interop.json' if args.paths == 2 else f'native-client-interop-{args.paths}links.json')
        target.write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        server.close()
        if process is not None and process.poll() is None:
            try:
                process.stdin.close()
                process.wait(5)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(5)
        if process is not None:
            process.stdout.close()
            process.stderr.close()


if __name__ == '__main__':
    main()
