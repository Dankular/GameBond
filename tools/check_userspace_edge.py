"""Bounded persistent-runtime validation, capturing diagnostic executables only."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from gamebond.userspace import live_status, request_stop


def main(probe_command=None,capture_paths=None,capture_mode='selected',observe_seconds=0):
    if live_status():raise RuntimeError('A tunnel is already running; leave it untouched')
    with socket.create_connection(('www.microsoft.com',443),timeout=3):pass
    config=json.loads((ROOT/'configs/local-client.json').read_text())
    config['capture_mode']=capture_mode
    config['cod_executables']=capture_paths or [str(ROOT/'build/netstack-smoke.exe')]
    path=ROOT/'.runtime/edge195/validation-client.json'
    path.write_text(json.dumps(config,indent=2)+'\n')
    output=(ROOT/'.runtime/edge195/validation-runtime.log').open('w')
    process=subprocess.Popen([sys.executable,'-m','gamebond.userspace','--config',str(path)],cwd=ROOT,
                             stdout=output,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
    report={}
    try:
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            status=live_status()
            if status and status['pid']==process.pid and status['state']=='running':break
            if process.poll() is not None:raise RuntimeError('Runtime exited; inspect validation-runtime.log')
            time.sleep(.2)
        else:raise RuntimeError('Runtime did not start within 25 seconds')
        result=subprocess.run(probe_command or [str(ROOT/'build/gamebond-internet-probe.exe'),'--internet-probe'],
                              capture_output=True,text=True,timeout=25,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise RuntimeError(result.stderr)
        report=json.loads(result.stdout)
        if report['egress_ipv4']!=config['peer'][0]:raise RuntimeError('HTTPS did not exit through the configured VPS')
        observation_deadline=time.monotonic()+observe_seconds
        while time.monotonic()<observation_deadline:
            if process.poll() is not None:raise RuntimeError('Runtime exited during observation')
            time.sleep(.2)
        status=live_status()
        metrics_deadline=time.monotonic()+3
        while status and (not status.get('application') or
                min(status['application'].get('uploaded_bytes',0),status['application'].get('downloaded_bytes',0))<=0) and time.monotonic()<metrics_deadline:
            time.sleep(.1);status=live_status()
        if not status or not status.get('application'):raise RuntimeError('Application counters were not published')
        report['application']=status['application']
        if min(report['application']['uploaded_bytes'],report['application']['downloaded_bytes'])<=0:
            raise RuntimeError('Application counters did not observe the probe')
        report['healthy_links']=sum(p['healthy'] for p in status['transport']['paths'])
        report['peer']=config['peer']
        report['capture_mode']=capture_mode
        report['app_authorization']=status.get('app_authorization')
    finally:
        status=live_status()
        if status and status['pid']==process.pid:request_stop()
        try:process.wait(timeout=8)
        except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=3)
        output.close()
    with socket.create_connection(('www.microsoft.com',443),timeout=3):pass
    report['runtime_exit_code']=process.returncode
    report['stopped']=live_status() is None
    if process.returncode or not report['stopped']:raise RuntimeError('Runtime did not stop cleanly')
    final=json.loads((ROOT/'.runtime/userspace-status.json').read_text())
    if final.get('pid')==process.pid:
        report['final_authorization']=final.get('app_authorization')
        report['verified_application_traffic']=final.get('applications',[])
    evidence=('quic-capture-validation.json' if report.get('capture') else 'quic-proxy-validation.json') if probe_command else 'edge195-userspace-validation.json'
    if report.get('persistent_connections'):evidence='tcp-capacity-validation.json'
    if capture_mode=='all':evidence='all-apps-connectivity-validation.json'
    (ROOT/'evidence'/evidence).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
