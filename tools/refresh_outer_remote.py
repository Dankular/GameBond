"""Refresh only a confirmed stopped validation container, preserving its prior image."""
import copy
import http.client
import json
import socket
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
    image,name,expected=sys.argv[1:]
    if not image.startswith('gamebond:outer-') or not name.startswith('gamebond-outer-'):raise ValueError('Unexpected candidate identity')
    old=api('/containers/'+name+'/json')
    if old['Id']!=expected or old['State']['Running'] or old['Config']['Labels'].get('gamebond.purpose')!='isolated-outer-validation':
        raise RuntimeError('Only the exact stopped validation container may be refreshed')
    production=api('/containers/gamebond-server-1/json')
    config=copy.deepcopy(old['Config']);config.update(Image=image,HostConfig=old['HostConfig'],
        NetworkingConfig={'EndpointsConfig':{'gamebond_tunnel':{'Aliases':[name]}}})
    backup=name+'-saved-'+image[-12:]
    api('/containers/'+expected+'/rename?name='+backup,method='POST')
    created=api('/containers/create?name='+name,config)
    api('/containers/'+name+'/start',method='POST')
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        current=api('/containers/'+name+'/json')
        if current['State'].get('Health',{}).get('Status')=='healthy':break
        if current['State']['Status']=='exited':raise RuntimeError('Refreshed candidate exited')
        time.sleep(.5)
    else:raise RuntimeError('Refreshed candidate did not become healthy')
    live=api('/containers/gamebond-server-1/json')
    if live['Id']!=production['Id'] or not live['State']['Running']:raise RuntimeError('Production identity changed')
    print(json.dumps(dict(id=created['Id'],image=image,backup=backup,health='healthy',state_after_validation='running',production_unchanged=True)))

if __name__=='__main__':main()
