"""Temporary TLS-authenticated kernel-TCP reference, separate from tunnel endpoints."""
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def main():
    candidate=json.loads((ROOT/'.runtime/outer-stage/candidate.json').read_text());directory=ROOT/'.runtime/direct-benchmark';directory.mkdir(exist_ok=True)
    source=(ROOT/'tools/throughput_server.py').read_bytes();token=secrets.token_hex(32)
    script='SOURCE='+repr(source)+'\nTOKEN='+repr(token)+'\n'+'''
import json,subprocess,sys
from pathlib import Path
image,release=sys.argv[1:];name='gamebond-direct-benchmark'
release=Path(release)
assert str(release).startswith('/opt/gamebond/outer-validation/')
existing=subprocess.run(['docker','inspect',name],capture_output=True,text=True)
if existing.returncode==0:raise RuntimeError('Direct benchmark container already exists; inspect its exact state before reuse')
source=release/'direct-benchmark.py';source.write_bytes(SOURCE);source.chmod(0o600)
secret=release/'secrets/direct-benchmark.token';secret.write_text(TOKEN+'\\n');secret.chmod(0o600)
command=['docker','run','-d','--name',name,'--label','gamebond.purpose=isolated-direct-benchmark','--network','gamebond_tunnel',
 '--cap-drop','ALL','--security-opt','no-new-privileges:true','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=8m',
 '--pids-limit','32','--memory','128m','-p','9443:8080/tcp',
 '--mount',f'type=bind,src={source},dst=/run/benchmark/server.py,readonly',
 '--mount',f'type=bind,src={release}/configs/carrier-cert.pem,dst=/run/benchmark/cert.pem,readonly',
 '--mount',f'type=bind,src={release}/secrets/carrier-key.pem,dst=/run/benchmark/key.pem,readonly',
 '--mount',f'type=bind,src={secret},dst=/run/benchmark/token,readonly',
 '--entrypoint','python',image,'-u','/run/benchmark/server.py','--public','--cert','/run/benchmark/cert.pem','--key','/run/benchmark/key.pem','--token-file','/run/benchmark/token']
r=subprocess.run(command,capture_output=True,text=True,check=True)
print(json.dumps(dict(container=name,id=r.stdout.strip(),port=9443)))
'''
    ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',str(Path.home()/'Desktop/privkey.ppk'),'root@195.154.119.136']
    r=subprocess.run(ssh+[shlex.join(['python3','-',candidate['image'],candidate['release']])],input=script,capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode:raise RuntimeError(r.stderr)
    result=json.loads(r.stdout);result.update(peer=candidate['peer'][0],ca_file=candidate['ca_file'])
    (directory/'token').write_text(token+'\n');(directory/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
