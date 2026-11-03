"""Validate captured HTTPS keep-alives beyond the former 64-connection limit."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import time


def request(connection):
    connection.request('GET','/cdn-cgi/trace',headers={'Connection':'keep-alive'})
    response=connection.getresponse()
    body=response.read().decode()
    if response.status!=200:raise RuntimeError(f'HTTP {response.status}')
    return next(line[3:] for line in body.splitlines() if line.startswith('ip='))


def main():
    connections=[http.client.HTTPSConnection('www.cloudflare.com',timeout=8) for _ in range(96)]
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            first=list(pool.map(request,connections))
            # Reuse sockets after the original SOCKS handshake deadline has elapsed.
            time.sleep(11)
            if any(connection.sock is None for connection in connections):raise RuntimeError('HTTPS socket closed before reuse')
            sockets=[connection.sock for connection in connections]
            second=list(pool.map(request,connections))
            if any(connection.sock is not sock for connection,sock in zip(connections,sockets)):
                raise RuntimeError('An HTTPS connection had to reconnect')
        if len(set(first+second))!=1:raise RuntimeError('Inconsistent egress')
        print(json.dumps(dict(passed=True,protocol='https',persistent_connections=96,requests=192,idle_seconds=11,egress_ipv4=first[0])))
    finally:
        for connection in connections:connection.close()


if __name__=='__main__':main()
