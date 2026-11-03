"""Create an isolated candidate endpoint; never stop or modify production."""
import copy
import http.client
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

class Docker(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(20);self.sock.connect('/var/run/docker.sock')

def api(path,data=None,method=None):
    connection=Docker('localhost',timeout=20)
    connection.request(method or ('POST' if data is not None else 'GET'),path,json.dumps(data).encode() if data is not None else None,{'Content-Type':'application/json'})
    response=connection.getresponse();body=response.read();status=response.status;connection.close()
    if status>=400:raise RuntimeError(f'Docker {status}: {body.decode()}')
    return json.loads(body) if body else None

def main():
    image,session,public_ip=sys.argv[1:]
    if not image.startswith('gamebond:outer-') or len(session)!=32 or any(c not in '0123456789abcdef' for c in session):raise ValueError('Invalid candidate identity')
    ipaddress.IPv4Address(public_ip)
    production=api('/containers/gamebond-server-1/json');host=copy.deepcopy(production['HostConfig']);config=copy.deepcopy(production['Config'])
    if host['Privileged'] or host['NetworkMode']!='gamebond_tunnel' or not host['ReadonlyRootfs']:raise RuntimeError('Unexpected production isolation')
    old_release=config['Labels']['com.docker.compose.project.working_dir']
    if not old_release.startswith('/opt/gamebond/releases/'):raise ValueError('Unexpected source release')
    release=Path('/opt/gamebond/outer-validation')/session;release.mkdir(mode=0o700,parents=True)
    (release/'configs').mkdir(mode=0o700);(release/'secrets').mkdir(mode=0o700)
    sources={m['Destination']:Path(m['Source']) for m in production['Mounts']}
    data=json.loads(sources['/run/config/server.json'].read_text());data['session']=session
    data['stream_relays']=[dict(bind=['0.0.0.0',4443],mode='tls',cert_file='/run/config/carrier-cert.pem',key_file='/run/secrets/carrier-key.pem',max_clients=4),
                           dict(bind=['0.0.0.0',4444],mode='tcp',max_clients=4)]
    source=sources['/run/config/server.json'];relative=source.relative_to(old_release)
    target=release/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_text(json.dumps(data,indent=2)+'\n');target.chmod(0o600)
    source=sources['/run/secrets/gamebond.key'];target=release/source.relative_to(old_release)
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(source,target);target.chmod(0o600)
    # Generate the private key within an isolated offline container. Only its
    # public certificate is returned to the client workstation.
    generator='''
from datetime import datetime,timedelta,timezone
import ipaddress,sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'GameBond isolated edge')]);now=datetime.now(timezone.utc)
cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
.not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=30))
.add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(sys.argv[1]))]),False).sign(key,hashes.SHA256()))
private=Path('/out/secrets/carrier-key.pem');private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));private.chmod(0o600)
public=Path('/out/configs/carrier-cert.pem');public.write_bytes(cert.public_bytes(serialization.Encoding.PEM));public.chmod(0o644)
'''
    result=subprocess.run(['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL',
        '--mount',f'type=bind,src={release},dst=/out','--entrypoint','python',image,'-',public_ip],input=generator,text=True,capture_output=True,timeout=30)
    if result.returncode:raise RuntimeError(result.stderr)
    for mount in host.get('Mounts',[]):
        if not mount['Source'].startswith(old_release+'/'):raise ValueError('Unowned source mount')
        mount['Source']=str(release)+mount['Source'][len(old_release):]
    host['Binds']=[str(release)+binding[len(old_release):] for binding in host.get('Binds') or []
                   if binding.startswith(old_release+'/')]
    host['Binds'] += [f'{release}/configs/carrier-cert.pem:/run/config/carrier-cert.pem:ro',
                      f'{release}/secrets/carrier-key.pem:/run/secrets/carrier-key.pem:ro']
    host['PortBindings']={'4433/udp':[{'HostIp':'0.0.0.0','HostPort':'4434'}],
                          '4443/tcp':[{'HostIp':'0.0.0.0','HostPort':'443'}],
                          '4444/tcp':[{'HostIp':'0.0.0.0','HostPort':'8443'}]}
    name='gamebond-outer-'+session[:8]
    config.update(Image=image,Hostname=name,Labels={'gamebond.purpose':'isolated-outer-validation','gamebond.release':str(release)},
        HostConfig=host,ExposedPorts={'4433/udp':{},'4443/tcp':{},'4444/tcp':{}},
        NetworkingConfig={'EndpointsConfig':{'gamebond_tunnel':{'Aliases':[name]}}})
    created=api('/containers/create?name='+name,config)
    try:
        api('/containers/'+name+'/start',method='POST')
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            candidate=api('/containers/'+name+'/json')
            if candidate['State'].get('Health',{}).get('Status')=='healthy':break
            if candidate['State']['Status']=='exited':raise RuntimeError('Candidate server exited')
            time.sleep(.5)
        else:raise RuntimeError('Candidate did not become healthy')
    except BaseException:
        api('/containers/'+created['Id']+'?force=true',method='DELETE');raise
    current=api('/containers/gamebond-server-1/json')
    if current['Id']!=production['Id'] or not current['State']['Running']:raise RuntimeError('Production identity unexpectedly changed')
    print(json.dumps(dict(container=name,id=created['Id'],image=image,session=session,peer=[public_ip,4434],tls_port=443,tcp_port=8443,
        certificate=(release/'configs/carrier-cert.pem').read_text(),production_unchanged=True,release=str(release),health='healthy')),flush=True)

if __name__=='__main__':main()
