"""Edit only GameBond's project configuration; never the OS hosts or resolver."""
import ipaddress
import json
import os
from pathlib import Path
import secrets

from .dns import load_dns_config, normalize_name
_UNSET=object()


def save_profile(path,dns,*,expected=_UNSET):
    """Save a validated DNS profile without changing OS or live resolver state."""
    from .app import load_config
    from .atomic_io import replace_file
    from .windows_dns import _hostname
    path=Path(path);original=path.read_bytes();config=load_config(path,allow_unavailable_links=True)
    if config['role']!='client':raise ValueError('DNS management requires a client configuration')
    if expected is not _UNSET and config.get('dns')!=expected:raise RuntimeError('DNS settings changed; reload the saved profile before saving')
    validated=load_dns_config(dns)
    if validated is None:raise ValueError('DNS settings are required')
    for hostname in validated.records:_hostname(hostname)
    if validated.bind!=(config['client_tunnel_ip'],53):raise ValueError('DNS must use the client tunnel address on port 53')
    config['dns']=dict(enabled=validated.enabled,bind=list(validated.bind),records={name:{family:list(addresses) for family,addresses in records.items()} for name,records in validated.records.items()},
        ttl=validated.ttl,upstream=list(validated.upstream) if validated.upstream else None,workers=validated.workers,pending=validated.pending,timeout=validated.timeout)
    if path.read_bytes()!=original:raise RuntimeError('Configuration changed; try saving again')
    temporary=path.with_name(path.name+'.dns-'+secrets.token_hex(8))
    try:
        temporary.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8');load_config(temporary,allow_unavailable_links=True);replace_file(temporary,path)
    finally:temporary.unlink(missing_ok=True)
    return config


def manage(path, action, hostname=None, address=None):
    from .app import load_config
    path = Path(path).resolve(strict=True)
    config = load_config(path,allow_unavailable_links=True)
    if config['role'] != 'client':
        raise ValueError('DNS management requires a client configuration')
    missing = config.get('dns') is None
    dns = config.get('dns') or dict(enabled=False, bind=[config['client_tunnel_ip'], 53],
                                  records={}, ttl=0, upstream=None)
    if action == 'show':
        return {'dns': dns, 'applies': 'next client restart', 'os_settings_changed': False}
    if action == 'set':
        if hostname is None or address is None:
            raise ValueError('dns set requires an exact hostname and IP address')
        hostname = normalize_name(hostname)
        ip = ipaddress.ip_address(address)
        dns['records'].setdefault(hostname, {})['A' if ip.version == 4 else 'AAAA'] = [str(ip)]
        if missing:
            dns['enabled'] = True
    elif action == 'remove':
        if hostname is None or address is not None:
            raise ValueError('dns remove requires one exact hostname')
        hostname = normalize_name(hostname)
        if hostname not in dns['records']:
            raise ValueError('DNS hostname is not configured')
        del dns['records'][hostname]
        if not dns['records']:
            dns['enabled'] = False
    elif action in ('enable', 'disable'):
        if hostname is not None or address is not None:
            raise ValueError('dns enable/disable do not accept hostname arguments')
        dns['enabled'] = action == 'enable'
    else:
        raise ValueError('unknown DNS management action')
    load_dns_config(dns)
    config['dns'] = dns
    temporary = path.with_name(path.name + '.tmp-' + secrets.token_hex(8))
    try:
        with temporary.open('x', encoding='utf-8') as output:
            json.dump(config, output, indent=2)
            output.write('\n')
        load_config(temporary,allow_unavailable_links=True)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return {'dns': dns, 'applies': 'next client restart', 'os_settings_changed': False}
