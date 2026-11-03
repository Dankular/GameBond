"""Build a source-only image overlay, then replace only the GameBond endpoint."""
import hashlib
import io
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parents[1]

def main():
    import sys
    sys.path.insert(0,str(ROOT))
    from gamebond.userspace import live_status
    if live_status():raise RuntimeError('Stop the GameBond runtime before replacing its server')
    config=json.loads((ROOT/'configs/local-client.json').read_text())
    ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes',
         '-o','UserKnownHostsFile=.runtime/test-known-hosts','-i',str(Path.home()/'.ssh/privkey_from_ppk'),'root@'+config['peer'][0]]
    if config['peer'][0]=='195.154.119.136':
        ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',
             str(Path.home()/'Desktop/privkey.ppk'),'root@'+config['peer'][0]]
    def remote(arguments,data=None,timeout=30):
        result=subprocess.run(ssh+[shlex.join(arguments)],cwd=ROOT,input=data,capture_output=True,
                              timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace') or result.stdout.decode(errors='replace'))
        return result.stdout.decode()
    base=remote(['docker','inspect','--format','{{.Config.Image}}','gamebond-server-1']).strip()
    if not base.startswith('gamebond:'):raise RuntimeError('Unexpected GameBond base image')
    digest=hashlib.sha256(b''.join(p.read_bytes() for p in sorted((ROOT/'gamebond').glob('*.py')))).hexdigest()
    image='gamebond:bonding-fix-'+digest[:12]
    context=io.BytesIO()
    with tarfile.open(fileobj=context,mode='w') as archive:
        dockerfile=f'FROM {base}\nCOPY gamebond /app/gamebond\n'.encode()
        info=tarfile.TarInfo('Dockerfile');info.size=len(dockerfile);archive.addfile(info,io.BytesIO(dockerfile))
        for path in sorted((ROOT/'gamebond').glob('*.py')):archive.add(path,arcname='gamebond/'+path.name)
    build=remote(['docker','build','-t',image,'-'],context.getvalue(),timeout=120)
    print('Candidate image built:',image,flush=True)
    if live_status():raise RuntimeError('A tunnel started during the build; candidate retained, server left untouched')
    session=secrets.token_hex(16)
    result=json.loads(remote(['python3','-',image,session],(ROOT/'tools/apply_bonding_fix_remote.py').read_bytes(),timeout=80).splitlines()[-1])
    # On a rollback, the original image also uses this fresh session.
    for role in ('client','server'):
        path=ROOT/'configs'/('local-'+role+'.json')
        data=json.loads(path.read_text());data['session']=result['session']
        temporary=path.with_suffix('.bonding-fix.tmp');temporary.write_text(json.dumps(data,indent=2)+'\n');temporary.replace(path)
    result['source_sha256']=digest
    (ROOT/'evidence/bonding-fix-deployment.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    if not result['deployed']:raise SystemExit('Candidate failed health check; original image restored with fresh shared session')

if __name__=='__main__':main()
