"""Build a separate native edge image and stage only an owned validation VPS.

Production and the existing outer-transport validation endpoint stay untouched.
"""
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
    directory=ROOT/'.runtime/native-stage';directory.mkdir(parents=True,exist_ok=True);manifest=directory/'candidate.json'
    if manifest.exists():raise RuntimeError('Native candidate manifest exists; inspect the exact owned container before changing it')
    ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',str(Path.home()/'Desktop/privkey.ppk'),'root@195.154.119.136']
    def remote(args,data=None,timeout=30):
        result=subprocess.run(ssh+[shlex.join(args)],input=data,capture_output=True,timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace') or result.stdout.decode(errors='replace'))
        return result.stdout.decode()
    base=remote(['docker','inspect','--format','{{.Config.Image}}','gamebond-server-1']).strip()
    if not base.startswith('gamebond:'):raise RuntimeError('Unexpected production base image')
    binary=ROOT/'build/gamebond-native-edge-linux';entrypoint=ROOT/'tools/container-entrypoint.sh'
    digest=hashlib.sha256(binary.read_bytes()+entrypoint.read_bytes()).hexdigest();image='gamebond:native-'+digest[:12]
    context=io.BytesIO()
    with tarfile.open(fileobj=context,mode='w') as archive:
        dockerfile=(f'FROM {base}\nCOPY --chmod=0755 gamebond-native-edge /usr/local/bin/gamebond-native-edge\n'
            'COPY --chmod=0755 container-entrypoint /usr/local/bin/container-entrypoint\nENV GAMEBOND_NATIVE_EDGE=1 GOMEMLIMIT=192MiB\n').encode()
        info=tarfile.TarInfo('Dockerfile');info.size=len(dockerfile);archive.addfile(info,io.BytesIO(dockerfile))
        archive.add(binary,arcname='gamebond-native-edge');archive.add(entrypoint,arcname='container-entrypoint')
    remote(['docker','build','-t',image,'-'],context.getvalue(),timeout=120)
    print('Built isolated native image '+image,flush=True)
    result=json.loads(remote(['python3','-',image,secrets.token_hex(16)],(ROOT/'tools/stage_native_remote.py').read_bytes(),timeout=65).splitlines()[-1])
    result.update(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_source_sha256=digest)
    manifest.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
    if result.get('error'):raise RuntimeError('Owned native candidate failed startup; identity preserved in its manifest: '+result['error'])

if __name__=='__main__':main()
