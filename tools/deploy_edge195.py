"""Deploy a fresh Docker GameBond edge without changing the current client."""
import hashlib
import io
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parents[1]
HOST='195.154.119.136'
PLINK='C:/Program Files (x86)/PuTTY/plink.exe'

def remote(command,data=None,timeout=30):
    result=subprocess.run([PLINK,'-batch','-T','-i',str(Path.home()/'Desktop/privkey.ppk'),
                           'root@'+HOST,command],cwd=ROOT,input=data,capture_output=True,
                           timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace')+result.stdout.decode(errors='replace'))
    return result.stdout.decode()

def main():
    session=secrets.token_hex(16)
    stage=ROOT/'.runtime/edge195';stage.mkdir(parents=True,exist_ok=True)
    key=secrets.token_bytes(32)
    key_path=ROOT/'secrets/edge195.key'
    if key_path.exists():raise RuntimeError('Staged edge key already exists; inspect the prior deployment before replacing it')
    key_path.write_bytes(key)
    configs={}
    for role in ('client','server'):
        config=json.loads((ROOT/'configs'/('local-'+role+'.json')).read_text())
        config.update(session=session,bonding_mode=True,redundant_mode=False,bulk_rate_mbps=0)
        if role=='client':
            config['peer']=[HOST,4433];config['key_file']='secrets/edge195.key'
            config.pop('wintun_dll',None)
        configs[role]=config
        (stage/(role+'.json')).write_text(json.dumps(config,indent=2)+'\n')
    image='gamebond:edge-'+session[:12]
    release='/opt/gamebond/releases/'+session
    plan=dict(host=HOST,session=session,image=image,release=release,key_file='secrets/edge195.key')
    (stage/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    payload=io.BytesIO()
    with tarfile.open(fileobj=payload,mode='w:gz') as archive:
        for name in ['Dockerfile','pyproject.toml','compose.yaml','.dockerignore','tools/container-entrypoint.sh']:
            archive.add(ROOT/name,arcname=name)
        for path in sorted((ROOT/'gamebond').glob('*.py')):archive.add(path,arcname='gamebond/'+path.name)
        files={'configs/local-server.json':(json.dumps(configs['server'],indent=2)+'\n').encode(),
               'secrets/gamebond.key':key,
               'deploy.env':f'GAMEBOND_IMAGE={image}\nGAMEBOND_SERVER_CONFIG=./configs/local-server.json\nGAMEBOND_KEY_FILE=./secrets/gamebond.key\n'.encode()}
        for name,data in files.items():
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600
            archive.addfile(info,io.BytesIO(data))
    archive_path='/root/gamebond-edge-'+session+'.tar.gz'
    remote('umask 077; cat > '+shlex.quote(archive_path),payload.getvalue())
    script=f'''set -eu
umask 077
test -c /dev/net/tun
test -z "$(docker ps -a --filter name='^/gamebond-server-1$' --format '{{{{.Names}}}}')"
test ! -e {shlex.quote(release)}
mkdir -p /opt/gamebond/releases
mkdir -m 700 {shlex.quote(release)}
tar -xzf {shlex.quote(archive_path)} -C {shlex.quote(release)} --no-same-owner
chmod 700 {shlex.quote(release)}/secrets
chmod 600 {shlex.quote(release)}/secrets/gamebond.key
cd {shlex.quote(release)}
docker compose --env-file deploy.env config --quiet
docker compose --env-file deploy.env build > /root/gamebond-edge-build.log 2>&1
docker compose --env-file deploy.env up -d --no-build
attempt=0
until [ "$(docker inspect --format '{{{{.State.Health.Status}}}}' gamebond-server-1)" = healthy ]; do
 attempt=$((attempt+1))
 if [ "$attempt" -ge 45 ]; then docker logs --tail 30 gamebond-server-1; exit 1; fi
 sleep 1
done
rm -f {shlex.quote(archive_path)}
docker inspect --format '{{{{.Config.Image}}}} {{{{.State.Status}}}} {{{{.State.Health.Status}}}} privileged={{{{.HostConfig.Privileged}}}} network={{{{.HostConfig.NetworkMode}}}}' gamebond-server-1
'''
    (stage/'deploy.sh').write_text(script)
    print(remote('sh -s',script.encode(),timeout=240),flush=True)
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'gamebond').glob('*.py'))}
    evidence=dict(deployed=True,**plan,source_sha256=hashes)
    (ROOT/'evidence/edge195-deployment.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(dict(deployed=True,host=HOST,image=image,health='healthy')),flush=True)

if __name__=='__main__':main()
