"""Build and stage a parallel carrier endpoint while production stays running."""
import hashlib
import io
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import tarfile
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    directory=ROOT/'.runtime/outer-stage';directory.mkdir(parents=True,exist_ok=True)
    manifest=directory/'candidate.json'
    refresh=sys.argv[1:]==['--refresh']
    if manifest.exists() and not refresh:raise RuntimeError('A candidate manifest exists; inspect that exact container before staging another')
    if refresh and not manifest.exists():raise RuntimeError('No existing candidate to refresh')
    ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',str(Path.home()/'Desktop/privkey.ppk'),'root@195.154.119.136']
    def remote(args,data=None,timeout=30):
        result=subprocess.run(ssh+[shlex.join(args)],input=data,capture_output=True,timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace') or result.stdout.decode(errors='replace'))
        return result.stdout.decode()
    base=remote(['docker','inspect','--format','{{.Config.Image}}','gamebond-server-1']).strip()
    if not base.startswith('gamebond:'):raise RuntimeError('Unexpected production image')
    paths=sorted((ROOT/'gamebond').glob('*.py'));digest=hashlib.sha256(b''.join(p.read_bytes() for p in paths)).hexdigest()
    image='gamebond:outer-'+digest[:12];context=io.BytesIO()
    with tarfile.open(fileobj=context,mode='w') as archive:
        dockerfile=f'FROM {base}\nCOPY gamebond /app/gamebond\n'.encode()
        info=tarfile.TarInfo('Dockerfile');info.size=len(dockerfile);archive.addfile(info,io.BytesIO(dockerfile))
        for path in paths:archive.add(path,arcname='gamebond/'+path.name)
    remote(['docker','build','-t',image,'-'],context.getvalue(),timeout=120)
    print('Built isolated image '+image,flush=True)
    if refresh:
        result=json.loads(manifest.read_text())
        result.update(json.loads(remote(['python3','-',image,result['container'],result['id']],
            (ROOT/'tools/refresh_outer_remote.py').read_bytes(),timeout=80).splitlines()[-1]))
        certificate=Path(result['ca_file'])
    else:
        result=json.loads(remote(['python3','-',image,secrets.token_hex(16),'195.154.119.136'],
            (ROOT/'tools/stage_outer_remote.py').read_bytes(),timeout=80).splitlines()[-1])
        certificate=directory/'edge-ca.pem';certificate.write_text(result.pop('certificate'),encoding='ascii')
    result.update(ca_file=str(certificate),source_sha256=digest)
    manifest.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)

if __name__=='__main__':main()
