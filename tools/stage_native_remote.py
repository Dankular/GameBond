"""Docker-namespace native candidate creation. Executed on the owned VPS."""
import json
from pathlib import Path
import shutil
import sys
import time

# The standalone transport deliberately has no application/client dependencies.
import http.client
import socket
class Docker(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(20);self.sock.connect('/var/run/docker.sock')
def api(path,data=None,method=None):
    connection=Docker('localhost',timeout=20);connection.request(method or ('POST' if data is not None else 'GET'),path,json.dumps(data).encode() if data is not None else None,{'Content-Type':'application/json'})
    response=connection.getresponse();body=response.read();status=response.status;connection.close()
    if status>=400:raise RuntimeError(f'Docker {status}: {body.decode()}')
    return json.loads(body) if body else None

def main():
    image,session=sys.argv[1:]
    if not image.startswith('gamebond:native-') or len(session)!=32 or any(c not in '0123456789abcdef' for c in session):raise ValueError('Invalid native candidate identity')
    production=api('/containers/gamebond-server-1/json')
    if not production['State']['Running'] or production['HostConfig']['Privileged'] or production['HostConfig']['NetworkMode']!='gamebond_tunnel':raise RuntimeError('Unexpected production topology')
    mounts={m['Destination']:Path(m['Source']) for m in production['Mounts']}
    release=Path('/opt/gamebond/native-validation')/session;release.mkdir(mode=0o700,parents=True)
    (release/'configs').mkdir(mode=0o700);(release/'secrets').mkdir(mode=0o700)
    config=json.loads(mounts['/run/config/server.json'].read_text());config['session']=session
    if config.get('stream_relays'):raise RuntimeError('Native carrier companion not integrated; refusing to silently discard configured relays')
    config.pop('stream_relays',None)
    target=release/'configs/server.json';target.write_text(json.dumps(config,indent=2)+'\n');target.chmod(0o600)
    shutil.copyfile(mounts['/run/secrets/gamebond.key'],release/'secrets/gamebond.key');(release/'secrets/gamebond.key').chmod(0o600)
    name='gamebond-native-'+session[:8]
    spec=dict(Image=image,Hostname=name,Labels={'gamebond.purpose':'isolated-native-validation','gamebond.release':str(release)},
        Env=['GAMEBOND_NATIVE_EDGE=1','GOMEMLIMIT=192MiB','PYTHONUNBUFFERED=1','PYTHONDONTWRITEBYTECODE=1'],
        ExposedPorts={'4433/udp':{}},Healthcheck={'Test':['CMD-SHELL','test -f /tmp/gamebond-ready && kill -0 "$(cat /tmp/gamebond.pid)"'],'Interval':2000000000,'Timeout':1000000000,'Retries':3,'StartPeriod':2000000000},
        HostConfig=dict(NetworkMode='gamebond_tunnel',ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=['NET_ADMIN'],Memory=268435456,PidsLimit=64,
            Tmpfs={'/tmp':'rw,noexec,nosuid,size=64m,mode=1777'},RestartPolicy={'Name':'no'},Sysctls={'net.ipv4.ip_forward':'1'},
            Devices=[{'PathOnHost':'/dev/net/tun','PathInContainer':'/dev/net/tun','CgroupPermissions':'rwm'}],
            Binds=[f'{release}/configs/server.json:/run/config/server.json:ro',f'{release}/secrets/gamebond.key:/run/secrets/gamebond.key:ro'],
            PortBindings={'4433/udp':[{'HostIp':'0.0.0.0','HostPort':'4435'}]}),
        NetworkingConfig={'EndpointsConfig':{'gamebond_tunnel':{'Aliases':[name]}}})
    created=api('/containers/create?name='+name,spec)
    result=dict(container=name,id=created['Id'],image=image,session=session,peer=['195.154.119.136',4435],release=str(release),production_id=production['Id'])
    try:
        api('/containers/'+created['Id']+'/start',method='POST');deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            current=api('/containers/'+created['Id']+'/json');result['state']=current['State']['Status'];result['health']=current['State'].get('Health',{}).get('Status')
            if result['health']=='healthy':break
            if not current['State']['Running']:raise RuntimeError('Native candidate exited during startup')
            time.sleep(.5)
        else:raise RuntimeError('Native candidate health deadline elapsed')
    except Exception as exc:result['error']=str(exc)
    current=api('/containers/gamebond-server-1/json');result['production_unchanged']=current['Id']==production['Id'] and current['State']['Running']
    print(json.dumps(result),flush=True)

if __name__=='__main__':main()
