"""Application routing configuration shared by the widget and backend."""
import ntpath
from pathlib import Path
import sys


def normalize_apps(applications):
    result=[];seen=set()
    for application in applications:
        if not isinstance(application,str):raise ValueError('Choose executable files')
        application=ntpath.normpath(application.strip())
        if not ntpath.isabs(application) or not ntpath.splitdrive(application)[0] or not application.lower().endswith('.exe') or '\0' in application:
            raise ValueError('Each application must have a full .exe path')
        key=application.casefold()
        if key not in seen:result.append(application);seen.add(key)
    return result


def proxy_configuration(config,address,root,executable=None,netstack_executable=None):
    mode=config.get('capture_mode','all')
    if mode not in ('all','selected'):raise ValueError('Choose All apps or Selected apps')
    root=Path(root);carrier=Path(executable or sys.executable)
    # The carrier and helpers must never capture their own upstream sockets.
    excluded=[str(carrier),str(carrier.with_name('python.exe')),str(carrier.with_name('pythonw.exe')),
              str(root/'build/gamebond-netstack.exe'),str(root/'.runtime/userspace-proxy/ProxiFyre.exe')]
    if netstack_executable:excluded.append(str(netstack_executable))
    apps=[''] if mode=='all' else normalize_apps(config.get('cod_executables',[]))+[str(root/'build/gamebond-internet-probe.exe')]
    return dict(logLevel='Info',bypassLan=False,excludes=list(dict.fromkeys(excluded)),proxies=[dict(
        appNames=list(dict.fromkeys(apps)),socks5ProxyEndpoint=address,socks5Transport='TCP',
        supportedProtocols=['TCP','UDP'],supportedAddressFamilies=['IPv4'])])
