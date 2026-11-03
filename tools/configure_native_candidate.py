"""Change only measured startup/queue settings on the exact isolated native VPS."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--initial-rate',type=float,default=1);parser.add_argument('--bulk-age-ms',type=int,default=100);args=parser.parse_args()
    if not .05<=args.initial_rate<=100 or not 100<=args.bulk_age_ms<=2000:raise ValueError('Invalid isolated tuning bounds')
    path=ROOT/'.runtime/native-stage/candidate.json';candidate=json.loads(path.read_text())
    script='''
import hashlib,json,subprocess,sys,time
from pathlib import Path
name,expected,initial,age=sys.argv[1:]
def run(args):return subprocess.run(args,capture_output=True,text=True,check=True).stdout
def inspect(n):return json.loads(run(['docker','inspect',n]))[0]
c=inspect(name);production=inspect('gamebond-server-1')
if c['Id']!=expected or c['Config']['Labels'].get('gamebond.purpose')!='isolated-native-validation':raise RuntimeError('Unexpected native candidate identity')
release=Path(c['Config']['Labels']['gamebond.release'])
if not str(release).startswith('/opt/gamebond/native-validation/'):raise RuntimeError('Unexpected native config ownership')
config=release/'configs/server.json';original=config.read_text();backup=release/'configs/before-throughput.json'
if not backup.exists():backup.write_text(original);backup.chmod(0o600)
settings=json.loads(original);settings['bonding_initial_rate_mbps']=float(initial);settings['queues']['0']['max_age_ms']=int(age)
run(['docker','stop','--time','8',expected]);assert not inspect(expected)['State']['Running']
config.write_text(json.dumps(settings,indent=2)+'\\n');config.chmod(0o600);run(['docker','start',expected])
deadline=time.monotonic()+30
while time.monotonic()<deadline:
 current=inspect(expected)
 if current['State'].get('Health',{}).get('Status')=='healthy':break
 if not current['State']['Running']:raise RuntimeError('Owned candidate exited after configuration update')
 time.sleep(.5)
else:raise RuntimeError('Owned native candidate did not recover health')
assert inspect('gamebond-server-1')['Id']==production['Id'] and inspect('gamebond-server-1')['State']['Running']
print(json.dumps(dict(container=name,id=expected,initial_rate_mbps=float(initial),bulk_age_ms=int(age),config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),health='healthy',production_unchanged=True)))
'''
    ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',str(Path.home()/'Desktop/privkey.ppk'),'root@195.154.119.136']
    result=subprocess.run(ssh+[shlex.join(['python3','-',candidate['container'],candidate['id'],str(args.initial_rate),str(args.bulk_age_ms)])],input=script,capture_output=True,text=True,timeout=50,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise RuntimeError(result.stderr)
    record=json.loads(result.stdout.splitlines()[-1]);candidate['tuning']=record;path.write_text(json.dumps(candidate,indent=2)+'\n');print(json.dumps(record))

if __name__=='__main__':main()
