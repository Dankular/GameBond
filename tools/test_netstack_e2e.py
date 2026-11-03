"""Netstack -> real encrypted GameBond loopback paths -> netstack.

Uses fresh ephemeral keys/session, no production configs, adapters or routes.
Blackholes path 0 halfway through replicated UDP echo traffic.
"""
import json
import os
from pathlib import Path
import queue
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
HIDDEN=getattr(subprocess,'CREATE_NO_WINDOW',0)
sys.path.insert(0, str(ROOT))
from gamebond.transport import Node, OVERHEAD, BOND_OVERHEAD, HEADER, DATA, STRIPED
from gamebond.policy import Classifier, QueuePolicy


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        part = stream.read(length - len(data))
        if not part:
            raise EOFError('netstack IPC closed')
        data.extend(part)
    return bytes(data)


def main(wan_endpoint=None, download_case=None):
    wan = wan_endpoint is not None
    capture = download_case is not None or sys.argv[1:] in (['--capture'], ['--wan'], ['--wan-direct'])
    direct = download_case is not None and os.environ.get('GAMEBOND_TEST_DIRECT_STACK') == '1'
    if sys.argv[1:] and not capture:
        raise ValueError('only --capture is supported')
    options = dict(bonding_mode=True, mtu=1280 + OVERHEAD + BOND_OVERHEAD,
                   initial_rate_mbps=4, max_rate_mbps=8,
                   probe_interval=.05, path_timeout=.3)
    key, session = ((wan_endpoint.key, wan_endpoint.session) if wan else
                    (secrets.token_bytes(32), secrets.token_bytes(16)))
    server = None if wan else Node(key, 'server', session, [('127.0.0.1', 0)], **options)
    configuration = json.loads((ROOT/'configs/local-client.json').read_text()) if wan else None
    bind = [tuple(b) for b in configuration['bind']] if wan else [('127.0.0.1',0)]*2
    if wan:
        options.update(interface_indices=configuration['interface_indices'], path_timeout=1)
    shared_link = wan and os.environ.get('GAMEBOND_TEST_SHARED_LINK') == '1'
    if shared_link:
        bind=[bind[0]]*2
        configuration['interface_indices']=[configuration['interface_indices'][0]]*2
        options['interface_indices']=configuration['interface_indices']
    if download_case is not None:
        bind=[bind[i] for i in download_case]
        options['interface_indices']=[configuration['interface_indices'][i] for i in download_case]
    client = Node(key, 'client', session, bind,
                  (wan_endpoint.host,wan_endpoint.port) if wan else server.addresses[0], **options)
    nodes = [client] if wan else [client,server]
    client_endpoints = tuple(client.addresses)
    stop, blackhole = threading.Event(), threading.Event()
    errors, frames = queue.Queue(), queue.Queue(maxsize=256)
    lock = threading.Lock()
    counts = [dict(bulk=[0, 0], game=[0, 0], blackholed=0, inbound_blackholed=0) for _ in nodes]
    child, proxy, probe, proxy_output, threads = None, None, None, None, []
    capture_ready = None
    udp_captured = 0
    ipc_metrics=dict(queue_peak=0,max_queue_age_ms=0,send_seconds=0,send_max_ms=0)
    classifiers = [Classifier({46: QueuePolicy(priority=True, replicate=True)},
                              game_ports=[8081]) for _ in nodes]
    if wan:
        original_receive = client._receive
        def receive_with_blackhole(index, packet, endpoint, **kwargs):
            if blackhole.is_set() and index == 0:
                counts[0]['inbound_blackholed'] += 1
                return
            return original_receive(index, packet, endpoint, **kwargs)
        client._receive = receive_with_blackhole
    def fail(exc):
        errors.put(repr(exc))
        stop.set()
    def monitor_connectivity():
        while not stop.wait(.5):
            try:
                with socket.create_connection(('www.microsoft.com', 443), timeout=2):
                    pass
            except OSError as exc:
                # Close only the test-owned capture process immediately.
                if proxy is not None and proxy.poll() is None: proxy.terminate()
                fail(RuntimeError(f'Connectivity watchdog stopped capture: {exc}'))
                return
    for index, node in enumerate(nodes):
        original = node._write
        def write(packet, path, index=index, original=original):
            path_index = (path.socket_index if index == 0 else
                          client_endpoints.index(path.endpoint))
            if blackhole.is_set() and path_index == 0:
                counts[index]['blackholed'] += 1
                return True  # Synthetic network loss after a successful send.
            result = original(packet, path)
            if result:
                kind = HEADER.unpack_from(packet)[3]
                if kind in (DATA, STRIPED):
                    counts[index]['game' if kind == DATA else 'bulk'][path_index] += 1
            return result
        node._write = write
    def receive(index):
        while not stop.is_set():
            try:
                packet = nodes[index].recv(.1)
                with lock:
                    child.stdin.write(struct.pack('!BH', index, len(packet)) + packet)
                    child.stdin.flush()
            except queue.Empty:
                continue
            except Exception as exc:
                if not stop.is_set(): fail(exc)
                return
    def read_frames():
        try:
            while not stop.is_set():
                endpoint, length = struct.unpack('!BH', read_exact(child.stdout, 3))
                if endpoint > 2 or not 0 < length <= 1280:
                    raise ValueError('invalid IPC frame')
                frames.put((endpoint, read_exact(child.stdout, length),time.perf_counter()), timeout=1)
                ipc_metrics['queue_peak']=max(ipc_metrics['queue_peak'],frames.qsize())
        except EOFError:
            frames.put(None)
        except Exception as exc:
            if not stop.is_set(): fail(exc)
    try:
        if server is not None: server.start()
        client.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (len((client if wan else server).stats()['paths']) == len(bind) and
                    all(p['healthy'] for node in nodes for p in node.stats()['paths'])):
                break
            time.sleep(.01)
        else:
            raise RuntimeError('two-path authenticated handshake timed out')
        mode = '--capture-stdio' if capture else '--transport-stdio'
        if direct: mode = '--direct-download-stdio'
        child = subprocess.Popen([str(ROOT / 'build/netstack-smoke.exe'), mode],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,creationflags=HIDDEN)
        threads = [threading.Thread(target=receive, args=(i,), daemon=True) for i in range(len(nodes))]
        threads.append(threading.Thread(target=read_frames, daemon=True))
        for thread in threads: thread.start()
        deadline = time.monotonic() + (35 if wan else 16)
        while not stop.is_set() and time.monotonic() < deadline:
            if capture_ready is not None and probe is None:
                log = capture_ready / 'logs/logfile.txt'
                if proxy.poll() is not None:
                    raise RuntimeError('ProxiFyre exited; inspect .runtime/proxifyre-e2e/console.txt')
                if log.exists() and 'ProxiFyre Service is running' in log.read_text(errors='replace'):
                    probe = subprocess.Popen([str(ROOT / 'build/gamebond-capture-probe.exe'), '--download-probe' if download_case is not None else '--host-probe'],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,creationflags=HIDDEN)
            if probe is not None and probe.poll() is not None:
                break
            try:
                frame = frames.get(timeout=.1)
            except queue.Empty:
                if child.poll() is not None: break
                continue
            if frame is None: break
            endpoint, packet, framed_at = frame
            ipc_metrics['max_queue_age_ms']=max(ipc_metrics['max_queue_age_ms'],(time.perf_counter()-framed_at)*1000)
            if endpoint == 2:
                if capture:
                    ready = json.loads(packet)
                    capture_ready = ROOT / '.runtime/proxifyre-e2e'
                    capture_ready.mkdir(parents=True, exist_ok=True)
                    source = Path('C:/Program Files/ProxiFyre')
                    for name in ('ProxiFyre.exe', 'ProxiFyre.exe.config', 'ProxiFyre.Configuration.dll',
                                 'Newtonsoft.Json.dll', 'NLog.dll', 'NLog.config', 'socksify.dll', 'Topshelf.dll'):
                        shutil.copy2(source / name, capture_ready / name)
                    shutil.copy2(ROOT / 'build/netstack-smoke.exe', ROOT / 'build/gamebond-capture-probe.exe')
                    configuration = dict(logLevel='Info', bypassLan=False, excludes=[], proxies=[dict(
                        appNames=['gamebond-capture-probe'], socks5ProxyEndpoint=ready['socks'],
                        socks5Transport='TCP', supportedProtocols=['TCP','UDP'],
                        supportedAddressFamilies=['IPv4'])])
                    assert configuration['proxies'][0]['appNames'] == ['gamebond-capture-probe']
                    (capture_ready / 'app-config.json').write_text(json.dumps(configuration, indent=2))
                    # Remove old readiness text from this test-owned log only.
                    log = capture_ready / 'logs/logfile.txt'
                    if log.exists(): log.write_text('')
                    proxy_output = (capture_ready / 'console.txt').open('w')
                    proxy = subprocess.Popen([str(capture_ready / 'ProxiFyre.exe'), '--allow-not-admin'],
                                             cwd=capture_ready, stdout=proxy_output, stderr=subprocess.STDOUT,creationflags=HIDDEN)
                    monitor = threading.Thread(target=monitor_connectivity, daemon=True)
                    threads.append(monitor)
                    monitor.start()
                    continue
                if packet != b'blackhole-path-0': raise ValueError('unknown phase')
                blackhole.set()
                continue
            if capture and download_case is None and endpoint == 0 and packet[9] == 17:
                udp_captured += 1
                if udp_captured == 51: blackhole.set()
            classification = classifiers[endpoint].classify(packet)
            send_started=time.perf_counter()
            if not nodes[endpoint].send(packet, replicate=classification.policy.replicate,
                                        flow_id=classification.info.flow):
                raise RuntimeError('transport could not send IP packet')
            send_seconds=time.perf_counter()-send_started
            ipc_metrics['send_seconds']+=send_seconds
            ipc_metrics['send_max_ms']=max(ipc_metrics['send_max_ms'],send_seconds*1000)
        if not errors.empty(): raise RuntimeError(errors.get())
        if capture and not direct:
            if probe is None: raise RuntimeError('ProxiFyre did not become ready')
            output, stderr_bytes = probe.communicate(timeout=2)
            if probe.returncode: raise RuntimeError('capture probe failed: '+stderr_bytes.decode(errors='replace'))
            stderr = output.decode()
        else:
            child.wait(timeout=3)
            stderr = child.stderr.read().decode('utf-8', errors='replace')
            if child.returncode: raise RuntimeError(f'netstack failed: {stderr}')
        if not errors.empty(): raise RuntimeError(errors.get())
        smoke = json.loads(stderr)
        assert smoke['passed'] and (download_case is not None or blackhole.is_set()), 'missing echo or failover phase'
        for index, node in enumerate(nodes):
            stats = node.stats()
            if download_case is None:
                assert all(n > 0 for n in counts[index]['bulk']), 'TCP did not use both paths'
                assert all(n > 0 for n in counts[index]['game']), 'UDP did not replicate on both paths'
                assert counts[index]['blackholed'] > 0, 'blackhole was not exercised'
                assert stats['duplicates'] > 0, 'deduplication was not exercised'
            assert stats['auth_failures'] == 0 and stats['receive_drops'] == 0
        report = dict(passed=True, observed_at=datetime.now(timezone.utc).isoformat(),
                      scope=('physical Windows uplinks to isolated VPS' if wan else
                             'local end-to-end; real encrypted UDP sockets on loopback'),
                      netstack=smoke, directions=counts, client=client.stats(),
                      server=None if wan else server.stats(),
                      physical_links_tested=wan, proxifyre_capture_tested=capture and not direct,
                      direct_stack=direct)
        report['shared_physical_link']=shared_link
        report['ipc_metrics']=ipc_metrics
        evidence_name = ('bonding-download-'+''.join(map(str,download_case))+'.json' if download_case is not None else 'netstack-wan-e2e.json' if wan else
                         'netstack-capture-e2e.json' if capture else 'netstack-e2e.json')
        if direct:evidence_name=evidence_name.replace('.json','-direct.json')
        if shared_link:evidence_name=evidence_name.replace('.json','-shared-link.json')
        (ROOT / 'evidence' / evidence_name).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(dict(passed=True, netstack=smoke, directions=counts)))
    finally:
        stop.set()
        for process in (probe, proxy):
            if process is not None:
                if process.poll() is None: process.terminate()
                process.wait(timeout=3)
        if proxy_output is not None: proxy_output.close()
        if child is not None:
            if child.poll() is None: child.kill()
            child.wait(timeout=3)
        for node in nodes: node.close()
        for thread in threads: thread.join(timeout=1)
        if child is not None:
            for stream in (child.stdin, child.stdout, child.stderr):
                try:stream.close()
                except OSError:pass  # Child already exited; a flushed pipe can be broken.


if __name__ == '__main__':
    if sys.argv[1:] in (['--download-benchmark'],['--download-bonded'],['--download-starlink'],['--download-phone']):
        from netstack_wan import WanEndpoint
        cases={'--download-bonded':[[0,1]],'--download-starlink':[[0]],'--download-phone':[[1]],
               '--download-benchmark':[[0],[1],[0,1]]}[sys.argv[1]]
        for case in cases:
            with WanEndpoint(secrets.token_bytes(32),secrets.token_bytes(16)) as endpoint:
                main(endpoint,download_case=case)
    elif sys.argv[1:] in (['--wan'], ['--wan-direct']):
        from netstack_wan import WanEndpoint
        with WanEndpoint(secrets.token_bytes(32),secrets.token_bytes(16)) as endpoint:
            main(endpoint)
    else:
        main()
