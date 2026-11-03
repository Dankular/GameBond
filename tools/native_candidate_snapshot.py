"""Read the exact owned native container's daemon state, metrics and CPU time."""
import json
from pathlib import Path
import shlex
import subprocess
ROOT=Path(__file__).resolve().parents[1]

def snapshot(candidate_path='.runtime/native-stage/candidate.json'):
    candidate=json.loads((ROOT/candidate_path).read_text())
    script='''
import json,subprocess,sys,time
name,expected=sys.argv[1:]
def run(args):return subprocess.run(args,capture_output=True,text=True,check=True).stdout
c=json.loads(run(['docker','inspect',name]))[0]
if c['Id']!=expected or c['Config']['Labels'].get('gamebond.purpose')!='isolated-native-validation':raise RuntimeError('Native candidate identity mismatch')
probe="import json,os; from pathlib import Path; pid=int(Path('/tmp/gamebond.pid').read_text()); cmd=Path('/proc')/str(pid)/'cmdline'; assert b'/usr/local/bin/gamebond-native-edge' in cmd.read_bytes(); data=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split(); c=json.loads(Path('/run/config/server.json').read_text()); print(json.dumps(dict(pid=pid,cpu_seconds=(int(data[11])+int(data[12]))/os.sysconf('SC_CLK_TCK'),initial_rate_mbps=c.get('bonding_initial_rate_mbps',1),bulk_age_ms=c['queues']['0']['max_age_ms'])))"
daemon=json.loads(run(['docker','exec',name,'python','-c',probe])) if c['State']['Running'] else None
latest=None
for line in run(['docker','logs','--tail','4',name]).splitlines():
 try:row=json.loads(line)
 except ValueError:continue
 if row.get('transport'):latest=row
print(json.dumps(dict(observed_at=time.time(),container=name,id=c['Id'],state=c['State']['Status'],started_at=c['State']['StartedAt'],health=c['State'].get('Health',{}).get('Status'),daemon=daemon,metrics=latest)))
'''
    ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',str(Path.home()/'Desktop/privkey.ppk'),'root@195.154.119.136']
    result=subprocess.run(ssh+[shlex.join(['python3','-',candidate['container'],candidate['id']])],input=script,capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise RuntimeError(result.stderr)
    return json.loads(result.stdout.splitlines()[-1])

if __name__=='__main__':
    result=snapshot();(ROOT/'evidence/native-server-current.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ('state','health','daemon')}))
    if result['metrics']:
        print(json.dumps([dict(endpoint=p['Endpoint'],rate_mbps=p['Budget']['rate_mbps'],delivered_bytes=p['Budget']['delivered_bytes'],expired_packets=p['Budget']['expired_packets'],backoffs=p['Budget']['backoffs']) for p in result['metrics']['transport']['paths']]))
