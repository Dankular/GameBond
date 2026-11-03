"""Start the known isolated container and a bounded private-only benchmark service."""
import json
import argparse
from pathlib import Path
import shlex
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--candidate',default='.runtime/outer-stage/candidate.json');args=parser.parse_args()
    path=ROOT/args.candidate;candidate=json.loads(path.read_text())
    source=(ROOT/'tools/throughput_server.py').read_bytes()
    script='SERVER_SOURCE='+repr(source)+'\n'+'''
import json,subprocess,sys,time
name,expected,purpose=sys.argv[1:]
def inspect(name):return json.loads(subprocess.run(['docker','inspect',name],capture_output=True,text=True,check=True).stdout)[0]
c=inspect(name);production=inspect('gamebond-server-1')
if purpose not in ('isolated-outer-validation','isolated-native-validation') or c['Id']!=expected or c['Config']['Labels'].get('gamebond.purpose')!=purpose:raise RuntimeError('Unexpected candidate identity')
if not c['State']['Running']:subprocess.run(['docker','start',name],check=True,capture_output=True)
deadline=time.monotonic()+45
while time.monotonic()<deadline:
 c=inspect(name)
 if c['State'].get('Health',{}).get('Status')=='healthy':break
 if c['State']['Status']=='exited':raise RuntimeError('Candidate exited')
 time.sleep(.5)
else:raise RuntimeError('Candidate not healthy')
check="import json,os; from pathlib import Path; p=Path('/tmp/throughput-ready.json'); r=json.loads(p.read_text()) if p.exists() else {}; pid=r.get('pid',0); cmd=Path('/proc')/str(pid)/'cmdline'; print(json.dumps(dict(alive=bool(pid and cmd.exists() and b'/tmp/throughput_server.py' in cmd.read_bytes()),record=r)))"
r=subprocess.run(['docker','exec',name,'python','-c',check],capture_output=True,text=True,check=True)
existing=json.loads(r.stdout)
if not existing['alive']:
 writer="import sys; from pathlib import Path; Path('/tmp/throughput_server.py').write_bytes(sys.stdin.buffer.read())"
 subprocess.run(['docker','exec','-i',name,'python','-c',writer],input=SERVER_SOURCE,check=True)
 subprocess.run(['docker','exec','-d',name,'python','-u','/tmp/throughput_server.py'],check=True)
 for _ in range(30):
  r=subprocess.run(['docker','exec',name,'python','-c',check],capture_output=True,text=True,check=True);existing=json.loads(r.stdout)
  if existing['alive'] and existing['record'].get('state')=='running':break
  time.sleep(.1)
 else:raise RuntimeError('Benchmark did not start')
assert inspect('gamebond-server-1')['Id']==production['Id']
print(json.dumps(dict(container=name,server=existing,production_unchanged=True)))
'''
    ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',str(Path.home()/'Desktop/privkey.ppk'),'root@195.154.119.136']
    purpose='isolated-native-validation' if candidate['container'].startswith('gamebond-native-') else 'isolated-outer-validation'
    result=subprocess.run(ssh+[shlex.join(['python3','-',candidate['container'],candidate['id'],purpose])],input=script,capture_output=True,text=True,timeout=60,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise RuntimeError(result.stderr)
    print(result.stdout.strip());candidate['state_after_validation']='running';path.write_text(json.dumps(candidate,indent=2)+'\n')

if __name__=='__main__':main()
