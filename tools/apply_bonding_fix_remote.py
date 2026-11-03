"""Replace only GameBond after the candidate image is built and validated."""
import copy
import http.client
import json
from pathlib import Path
import shutil
import socket
import sys
import time

class Docker(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(20);self.sock.connect('/var/run/docker.sock')

def api(path,data=None,method=None):
    connection=Docker('localhost',timeout=20)
    body=json.dumps(data).encode() if data is not None else None
    connection.request(method or ('POST' if data is not None else 'GET'),path,body,{'Content-Type':'application/json'})
    response=connection.getresponse();raw=response.read();status=response.status;connection.close()
    if status>=400:raise RuntimeError(f'Docker {status}: {raw.decode()}')
    return json.loads(raw) if raw else None

def main():
    image,session=sys.argv[1:]
    if not image.startswith('gamebond:bonding-fix-') or len(session)!=32 or any(c not in '0123456789abcdef' for c in session):
        raise ValueError('Invalid staged release identity')
    old=api('/containers/gamebond-server-1/json')
    host=copy.deepcopy(old['HostConfig']);config=copy.deepcopy(old['Config'])
    if host['Privileged'] or host['NetworkMode']!='gamebond_tunnel' or not host['ReadonlyRootfs']:
        raise RuntimeError('Unexpected production isolation; refusing replacement')
    old_release=config['Labels']['com.docker.compose.project.working_dir']
    if not old_release.startswith('/opt/gamebond/releases/'):raise ValueError('Unowned production release')
    release=Path('/opt/gamebond/releases')/session
    release.mkdir(mode=0o700)
    sources={m['Destination']:Path(m['Source']) for m in old['Mounts']}
    for destination in ('/run/config/server.json','/run/secrets/gamebond.key'):
        source=sources[destination]
        relative=source.relative_to(old_release)
        target=release/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if destination.endswith('server.json'):
            data=json.loads(source.read_text());data['session']=session
            target.write_text(json.dumps(data,indent=2)+'\n')
        else:shutil.copyfile(source,target)
        target.chmod(0o600)
    if (Path(old_release)/'compose.yaml').exists():shutil.copyfile(Path(old_release)/'compose.yaml',release/'compose.yaml')
    (release/'deploy.env').write_text(f'GAMEBOND_IMAGE={image}\nGAMEBOND_SERVER_CONFIG=./configs/local-server.json\nGAMEBOND_KEY_FILE=./secrets/gamebond.key\n')
    (release/'deploy.env').chmod(0o600)
    for mount in host.get('Mounts',[]):
        if not mount['Source'].startswith(old_release+'/'):raise ValueError('Unexpected host mount')
        mount['Source']=str(release)+mount['Source'][len(old_release):]
    for index,binding in enumerate(host.get('Binds') or []):
        if not binding.startswith(old_release+'/'):raise ValueError('Unexpected bind mount')
        host['Binds'][index]=str(release)+binding[len(old_release):]
    config['Image']=image
    config['Labels']['com.docker.compose.project.working_dir']=str(release)
    config['Labels']['com.docker.compose.project.config_files']=str(release/'compose.yaml')
    config['HostConfig']=host
    config['NetworkingConfig']={'EndpointsConfig':{'gamebond_tunnel':{'Aliases':['server','gamebond-server-1']}}}
    backup='gamebond-before-bonding-fix-'+session[:8]
    api('/containers/gamebond-server-1/stop?t=10',method='POST')
    api('/containers/gamebond-server-1/rename?name='+backup,method='POST')
    def start(configuration):
        api('/containers/create?name=gamebond-server-1',configuration)
        api('/containers/gamebond-server-1/start',method='POST')
        deadline=time.monotonic()+50
        while time.monotonic()<deadline:
            status=api('/containers/gamebond-server-1/json')
            if status['State'].get('Health',{}).get('Status')=='healthy':return
            if status['State']['Status']=='exited':break
            time.sleep(.5)
        raise RuntimeError('Replacement container did not become healthy')
    try:
        start(config)
    except BaseException:
        try:api('/containers/gamebond-server-1?force=true',method='DELETE')
        except RuntimeError:pass
        # Same fresh session/key/config, original image. The old server is kept
        # stopped for inspection; no unrelated container is touched.
        config['Image']=old['Config']['Image'];start(config)
        print(json.dumps(dict(deployed=False,rolled_back=True,session=session,image=config['Image'],release=str(release))),flush=True)
        return
    print(json.dumps(dict(deployed=True,session=session,image=image,release=str(release),backup=backup,health='healthy')),flush=True)

if __name__=='__main__':main()
