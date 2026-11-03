"""Controlled selected-app capture test for attribution, dedup and Protect."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond.userspace import live_status, request_stop

HIDDEN = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def wait_for(predicate, seconds=6):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate(live_status())
        if result:
            return result
        time.sleep(.15)
    raise RuntimeError('Timed out waiting for verified runtime evidence')


def main(profile='automatic'):
    if live_status():
        raise RuntimeError('An active tunnel is present; leave it untouched')
    with socket.create_connection(('1.1.1.1', 443), timeout=5):
        pass
    directory = ROOT / '.runtime' / 'notification-validation'
    directory.mkdir(parents=True, exist_ok=True)
    probe = directory / ('notification-probe-' + uuid.uuid4().hex[:10] + '.exe')
    shutil.copy2(ROOT / 'build/gamebond-netstack-attribution.exe', probe)
    config = json.loads((ROOT / 'configs/local-client.json').read_text())
    # The production peer has not yet received the optional link-policy protocol.
    config.pop('link_policies', None)
    config.update(capture_mode='selected', cod_executables=[str(probe)],
                  app_attribution_enabled=True, protection_enabled=True, app_rules={})
    config['app_rules']={str(probe):dict(outbound='allow',profile=profile)}
    config_path = directory / 'client.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    probe_environment = os.environ.copy()
    probe_environment.update(GAMEBOND_PROBE_TRACE_URL='https://1.1.1.1/cdn-cgi/trace',
                             GAMEBOND_PROBE_STUN_ADDRESS='162.159.207.0:3478')
    output = (directory / 'runtime.log').open('w')
    process = subprocess.Popen([sys.executable, '-m', 'gamebond.userspace', '--config', str(config_path)],
                               cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, creationflags=HIDDEN)
    report = dict(probe=str(probe), started_at=time.time(),profile=profile,passed=False)
    try:
        status = wait_for(lambda s: s if s and s['pid'] == process.pid and s['state'] == 'running' else None, 30)
        assert status['app_attribution']['available'], 'Attribution extension unavailable'
        report['tested_links'] = [p['interface_index'] for p in status['transport']['paths']]
        report['configured_links'] = status.get('configured_links')
        report['unavailable_links'] = status.get('unavailable_links')
        for _ in range(2):
            result = subprocess.run([str(probe), '--internet-probe'], capture_output=True, text=True,
                                    timeout=30, creationflags=HIDDEN, env=probe_environment)
            if result.returncode:
                raise RuntimeError('Probe failed: ' + result.stderr[-2000:])
            observed = json.loads(result.stdout)
            assert observed['egress_ipv4'] == config['peer'][0], observed
            assert observed['udp_egress_ipv4'] == config['peer'][0], observed
            report.setdefault('probes', []).append(observed)
        def attributed(s):
            if not s: return None
            events = [e for e in (s.get('app_events') or {}).get('events', [])
                      if e['application']['path'].casefold() == str(probe).casefold()]
            rows = [r for r in s.get('applications', []) if r['path'].casefold() == str(probe).casefold()]
            if len(events) == 1 and rows and sum(r['downloaded_bytes'] for r in rows) > 0:
                return dict(events=events, applications=rows)
        report['attribution'] = wait_for(attributed)
        status = live_status()
        report['qos']=status.get('qos')
        report['transport_classes']={key:status['transport'].get(key,0) for key in ('priority_tx_packets','priority_rx_first_packets','bonded_packets')}
        if profile in ('call','streaming'):
            name='call' if profile=='call' else 'stream'
            assert report['qos']['counters'].get('classified_'+name,0)>0,'Native app profile did not reach QoS'
            assert report['transport_classes']['priority_tx_packets']>0,'Upload priority not enforced'
            assert report['transport_classes']['priority_rx_first_packets']>0,'VPS return priority not enforced'
        denied_before = status['app_authorization']['denied']
        config['app_rules'] = {str(probe): dict(outbound='block', profile='automatic')}
        temporary = config_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(config, indent=2) + '\n')
        temporary.replace(config_path)
        time.sleep(1.5)
        blocked = subprocess.run([str(probe), '--internet-probe'], capture_output=True, text=True,
                                 timeout=30, creationflags=HIDDEN, env=probe_environment)
        assert blocked.returncode != 0, 'Blocked application unexpectedly succeeded'
        def denied(s):
            auth = s.get('app_authorization', {}) if s else {}
            matches = [r for r in auth.get('recent', []) if r.get('reason') == 'application_blocked'
                       and (r.get('application') or {}).get('path', '').casefold() == str(probe).casefold()]
            return matches if auth.get('denied', 0) > denied_before and matches else None
        report['blocked_decisions'] = wait_for(denied)
        report['capture_checks_complete'] = True
    finally:
        status = live_status()
        if status and status['pid'] == process.pid:
            request_stop()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate(); process.wait(timeout=3)
        output.close()
        report.update(runtime_exit_code=process.returncode, stopped=live_status() is None)
        name='app-notification-e2e.json' if profile=='automatic' else 'app-qos-'+profile+'-e2e.json'
        (ROOT / 'evidence' / name).write_text(json.dumps(report, indent=2) + '\n')
    with socket.create_connection(('1.1.1.1', 443), timeout=5):
        pass
    assert process.returncode == 0 and report['stopped'], 'Runtime cleanup failed'
    report['passed']=True;report['direct_connectivity_after_stop']=True
    (ROOT/'evidence'/name).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=('automatic','call','streaming'),default='automatic')
    main(parser.parse_args().profile)
