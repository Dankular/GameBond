"""Go client role against the Go server role, over loopback UDP (no Python peer).

Starts the Go receiver-probe as a bonded, sink-mode server and the Go client-probe
with N uplinks, sends COUNT numbered 1000-byte payloads and reports the server's
own count and first-to-last payload time. Use --rate to lift the 10/20 Mbit/s
sender ceiling when looking for the throughput limit. Loopback on one machine:
this shows implementation limits, not physical link behaviour.

    go -C native-edge build -o ../build/gamebond-native-receiver-probe.exe ./cmd/receiver-probe
    go -C native-edge build -o ../build/gamebond-native-client-probe.exe ./cmd/client-probe
    python tools/check_go_to_go.py [--paths N] [--send COUNT] [--rate MBIT]
"""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def exe(name):
    return str(ROOT / 'build' / (f'gamebond-native-{name}.exe' if sys.platform == 'win32' else f'gamebond-native-{name}'))


def spawn(name):
    return subprocess.Popen([exe(name)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--paths', type=int, choices=range(1, 9), default=2)
    parser.add_argument('--send', type=int, default=20000)
    parser.add_argument('--rate', type=float, default=10)
    parser.add_argument('--mtu', action='store_true')
    parser.add_argument('--policy', action='store_true')
    args = parser.parse_args()
    key, session = secrets.token_bytes(32), secrets.token_bytes(16)
    server = client = None
    try:
        server = spawn('receiver-probe')
        server.stdin.write(json.dumps(dict(key=key.hex(), session=session.hex(), bonded=True, sink=True, rate=args.rate)) + '\n')
        server.stdin.flush()
        address = json.loads(server.stdout.readline())['address']
        client = spawn('client-probe')
        client.stdin.write(json.dumps(dict(key=key.hex(), session=session.hex(), server=address, paths=args.paths,
                                           send=args.send, rate=args.rate, mtu=args.mtu, policy=args.policy)) + '\n')
        client.stdin.flush()
        assert json.loads(client.stdout.readline())['status'] == 'started'
        deadline = time.monotonic() + 60
        # The client reports only on quit; poll by waiting for the send to finish.
        time.sleep(1.0)
        while time.monotonic() < deadline:
            time.sleep(.25)
            # A fixed grace is enough: payloads at >=10 Mbit/s finish in seconds.
            if time.monotonic() - deadline + 60 > max(6, args.send * 8000 / (args.rate * 1e6 * args.paths) * 1.5 + 4):
                break
        client.stdin.write('x'); client.stdin.flush()
        creport = json.loads(client.stdout.readline())
        client.wait(5)
        server.stdin.write('x'); server.stdin.flush()
        sreport = json.loads(server.stdout.readline())
        server.wait(5)
        got = sreport['receiver']['PayloadPackets']
        seconds = sreport['payload_seconds']
        result = dict(uplinks=args.paths, rate=args.rate, mtu=args.mtu, policy=args.policy, sent=args.send, server_payloads=got,
                      server_seconds=round(seconds, 3), mbit_per_s=round(got * 1000 * 8 / seconds / 1e6, 2) if seconds else None,
                      client_ready=creport['ready_paths'], client_queue_expired=creport['transmit_queue']['Expired'],
                      server_malformed=sreport['receiver']['Malformed'], server_auth_errors=sreport['receiver']['AuthenticationErrors'])
        assert creport['ready_paths'] == args.paths, creport['ready_paths']
        assert sreport['receiver']['AuthenticationErrors'] == 0
        print(json.dumps(result))
    finally:
        for process in (client, server):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.stdout.close(); process.stderr.close()


if __name__ == '__main__':
    main()
