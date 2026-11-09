"""Go client probe -> Go server probe through a UDP relay that blackholes one uplink mid-run.

The relay gives every client source port its own upstream socket (so the server sees
distinct paths) and, between --cut and --restore seconds after the send starts,
drops everything to and from the first client source port. The check passes when the
server still receives at least --min-ratio of the sent payloads, the client reports
both paths ready again at the end if the path was restored, and nothing failed to
authenticate. Loopback only: it exercises the failover logic, not a physical link.

    python tools/check_go_failover.py [--send 20000] [--rate 10] [--cut 4] [--restore 10]
"""
import argparse
import json
import secrets
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def exe(name):
    return str(ROOT / 'build' / (f'gamebond-native-{name}.exe' if sys.platform == 'win32' else f'gamebond-native-{name}'))


def spawn(name):
    return subprocess.Popen([exe(name)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


class Relay:
    def __init__(self, server):
        self.server = server
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(('127.0.0.1', 0))
        self.address = self.front.getsockname()
        self.upstream = {}          # client addr -> socket
        self.first = None           # the client source port that gets blackholed
        self.blackhole = False
        self.dropped = 0
        self.stop = False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.stop:
            socks = [self.front] + list(self.upstream.values())
            ready, _, _ = select.select(socks, [], [], .1)
            for s in ready:
                try:
                    data, src = s.recvfrom(65535)
                except OSError:
                    continue
                if s is self.front:
                    if self.first is None:
                        self.first = src
                    if src not in self.upstream:
                        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        u.bind(('127.0.0.1', 0))
                        self.upstream[src] = u
                    if self.blackhole and src == self.first:
                        self.dropped += 1
                    else:
                        self.upstream[src].sendto(data, self.server)
                else:
                    client = next(c for c, u in self.upstream.items() if u is s)
                    if self.blackhole and client == self.first:
                        self.dropped += 1
                    else:
                        self.front.sendto(data, client)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--send', type=int, default=20000)
    p.add_argument('--rate', type=float, default=10)
    p.add_argument('--cut', type=float, default=4)
    p.add_argument('--restore', type=float, default=10, help='0 = never restore')
    p.add_argument('--failover', action='store_true', help='enable suspect-path replay on the client')
    p.add_argument('--echo', action='store_true', help='server echoes payloads back: exercises server -> client under the cut')
    p.add_argument('--min-ratio', type=float, default=.9)
    args = p.parse_args()
    key, session = secrets.token_bytes(32), secrets.token_bytes(16)
    server = client = relay = None
    try:
        server = spawn('receiver-probe')
        server.stdin.write(json.dumps(dict(key=key.hex(), session=session.hex(), bonded=True, sink=not args.echo, rate=args.rate, failover=args.failover)) + '\n')
        server.stdin.flush()
        host, port = json.loads(server.stdout.readline())['address'].rsplit(':', 1)
        relay = Relay((host, int(port)))
        client = spawn('client-probe')
        client.stdin.write(json.dumps(dict(key=key.hex(), session=session.hex(), server='%s:%d' % relay.address, paths=2, policymbps=50, failover=args.failover,
                                           send=args.send, rate=args.rate)) + '\n')
        client.stdin.flush()
        assert json.loads(client.stdout.readline())['status'] == 'started'
        start = time.monotonic()
        events = []
        send_seconds = args.send * 8000 / (args.rate * 1e6)
        while time.monotonic() - start < send_seconds + 4:
            t = time.monotonic() - start
            if not relay.blackhole and t >= args.cut and (not args.restore or t < args.restore):
                relay.blackhole = True; events.append(('cut', round(t, 2)))
            if relay.blackhole and args.restore and t >= args.restore:
                relay.blackhole = False; events.append(('restored', round(t, 2)))
            time.sleep(.05)
        client.stdin.write('x'); client.stdin.flush()
        creport = json.loads(client.stdout.readline())
        server.stdin.write('x'); server.stdin.flush()
        sreport = json.loads(server.stdout.readline())
        got = sreport['receiver']['PayloadPackets']
        result = dict(sent=args.send, server_payloads=got, ratio=round(got / args.send, 4), relay_dropped=relay.dropped, events=events,
                      client_ready_paths=creport['ready_paths'], server_auth_errors=sreport['receiver']['AuthenticationErrors'], server_duplicates=sreport['receiver'].get('Duplicates'),
                      client_failover={k: v for k, v in creport['sender'].items() if k.startswith('Failover')},
                      client_queue_expired=creport['transmit_queue']['Expired'])
        if args.echo:
            result['client_received_echoes'] = creport['receiver']['PayloadPackets']
        print(json.dumps(result))
        back = creport['receiver']['PayloadPackets'] / args.send if args.echo else 1
        ok = (relay.dropped > 0 and got / args.send >= args.min_ratio and back >= args.min_ratio and result['server_auth_errors'] == 0
              and (not args.restore or creport['ready_paths'] == 2))
        print('PASS' if ok else 'FAIL')
        return 0 if ok else 1
    finally:
        if relay:
            relay.stop = True
        for process in (client, server):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.stdout.close(); process.stderr.close()


if __name__ == '__main__':
    sys.exit(main())
