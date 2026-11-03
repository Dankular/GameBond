"""Isolated GameBond VPS test endpoint. No other VPN is used or controlled."""
import json
import os
import base64
from pathlib import Path
import secrets
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]

class WanEndpoint:
    def __init__(self, key, session):
        self.key, self.session = key, session
        self.host = json.loads((ROOT/'configs/local-client.json').read_text())['peer'][0]
        self.name = 'gamebond-netstack-e2e-' + secrets.token_hex(5)
        self.port = 44433
        self.ssh = ['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6',
                    '-o','ServerAliveInterval=3','-o','ServerAliveCountMax=2',
                    '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=.runtime/test-known-hosts',
                    '-i',str(Path.home()/'.ssh/privkey_from_ppk'), f'root@{self.host}']
        if self.host=='195.154.119.136':
            self.ssh=['C:/Program Files (x86)/PuTTY/plink.exe','-batch','-T','-i',
                      str(Path.home()/'Desktop/privkey.ppk'),'root@'+self.host]
        self.rows = []
        self.created = False
        self.ready_flag = False

    def command(self, args, *, data=None):
        result = subprocess.run(self.ssh+[shlex.join(args)],cwd=ROOT,input=data,
                                capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode:
            raise RuntimeError('SSH/Docker command failed: '+result.stderr.decode(errors='replace'))
        return result.stdout.decode()

    def __enter__(self):
        self.before = self.command(['docker','inspect','--format','{{.Id}} {{.State.StartedAt}}','gamebond-server-1']).strip()
        image = self.command(['docker','inspect','--format','{{.Config.Image}}','gamebond-server-1']).strip()
        if not image.startswith('gamebond:'): raise RuntimeError('Unexpected production image')
        bootstrap = ("import pathlib,time; p=pathlib.Path('/tmp/start.py'); "
                     "deadline=time.monotonic()+15\n"
                     "while not p.exists() and time.monotonic()<deadline: time.sleep(.05)\n"
                     "exec(compile(p.read_text(),str(p),'exec'))")
        args = ['docker','run','--rm','-d','--name',self.name,'--label','gamebond.role=netstack-e2e',
                '-e','GAMEBOND_TEST_INITIAL_MBPS='+os.environ.get('GAMEBOND_TEST_INITIAL_MBPS','1'),
                '-e','GAMEBOND_TEST_PROFILE='+os.environ.get('GAMEBOND_TEST_PROFILE','0'),
                '--network','gamebond_tunnel','--cap-drop','ALL','--cap-add','NET_ADMIN',
                '--device','/dev/net/tun:/dev/net/tun:rw','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
                '--security-opt','no-new-privileges:true','--memory','256m','--pids-limit','64',
                '-p',f'{self.port}:4433/udp','--entrypoint','python',image,'-u','-c',bootstrap]
        self.command(args)
        self.created = True
        # Test the actual workspace implementation on the VPS, rather than the
        # older production image's installed Python modules. Private tmpfs only.
        sources={p.name:base64.b64encode(p.read_bytes()).decode() for p in (ROOT/'gamebond').glob('*.py')}
        prelude=("import pathlib,base64,sys\n"
                 "package=pathlib.Path('/tmp/test-source/gamebond');package.mkdir(parents=True)\n"
                 f"sources={sources!r}\n"
                 "for name,data in sources.items(): (package/name).write_bytes(base64.b64decode(data))\n"
                 "sys.path.insert(0,'/tmp/test-source')\n")
        source = (prelude+f'KEY=bytes.fromhex({self.key.hex()!r})\nSESSION=bytes.fromhex({self.session.hex()!r})\n'
                  +(ROOT/'tools/netstack_wan_echo.py').read_text())
        try:
            # The fresh key exists only in the container's private tmpfs and memory.
            self.command(['docker','exec','-i',self.name,'python','-c',
                          "import sys,os;open('/tmp/start.py.pending','wb').write(sys.stdin.buffer.read());os.replace('/tmp/start.py.pending','/tmp/start.py')"],data=source.encode())
            deadline = time.monotonic()+12
            while time.monotonic()<deadline:
                lines = self.command(['docker','logs',self.name]).splitlines()
                for line in lines:
                    try: row = json.loads(line)
                    except ValueError: continue
                    if row.get('worker_error'): raise RuntimeError(row['worker_error'])
                    if row.get('ready'):
                        self.rows.append(row)
                        self.ready_flag = True
                        return self
                time.sleep(.1)
            raise RuntimeError('VPS test endpoint did not become ready')
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def __exit__(self, *_):
        try:
            if self.created:
                try:
                    if self.ready_flag:
                        latest = json.loads(self.command(['docker','exec',self.name,'cat','/tmp/result.json']))
                        self.rows.append(latest)
                finally:
                    try:self.command(['docker','rm','-f',self.name])
                    except RuntimeError as error:
                        if 'No such container' not in str(error):raise
                self.rows.append({'test_container_removed':True})
            after = self.command(['docker','inspect','--format','{{.Id}} {{.State.StartedAt}}','gamebond-server-1']).strip()
            self.rows.append({'production_unchanged':after==self.before})
            if after != self.before: raise RuntimeError('Production identity/start time changed')
        finally:
            (ROOT/'evidence/netstack-wan-server.json').write_text(json.dumps(self.rows,indent=2)+'\n')
