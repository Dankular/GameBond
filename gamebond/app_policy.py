"""Validated per-application policies for authenticated outbound tunnel flows.

This governs the GameBond SOCKS boundary. It is not a Windows host firewall:
unsolicited inbound services are not exposed by this tunnel.
"""
from dataclasses import dataclass
import hashlib
import json
import ntpath
import os
from pathlib import Path
import secrets
from typing import Mapping

PROFILES = {'automatic':'automatic', 'gaming':'game', 'streaming':'stream', 'call':'call', 'bulk':'bulk'}
MAX_RULES = 4096
MAX_CONFIG_BYTES = 4 * 1024 * 1024
CONFIG = Path(__file__).resolve().parents[1] / 'configs/local-client.json'


def canonical_path(path):
    if not isinstance(path,str) or not path or len(path)>32768 or '\0' in path:
        raise ValueError('Choose a full executable path')
    path=ntpath.normpath(path.strip())
    drive,_=ntpath.splitdrive(path)
    if not drive or not ntpath.isabs(path) or not path.lower().endswith('.exe'):
        raise ValueError('Application rules require a full .exe path')
    return ntpath.normcase(path)


def normalize_rule(rule):
    if not isinstance(rule,Mapping) or set(rule)-{'outbound','profile'}:
        raise ValueError('Application rules support outbound and profile settings')
    outbound=rule.get('outbound','allow');profile=rule.get('profile','automatic')
    if outbound not in ('allow','block'):raise ValueError('Outbound must be allow or block')
    if not isinstance(profile,str) or profile not in PROFILES:raise ValueError('Unknown application traffic profile')
    return dict(outbound=outbound,profile=profile)


def normalize_rules(rules):
    if not isinstance(rules,Mapping) or len(rules)>MAX_RULES:raise ValueError('Invalid application rule list')
    result={}
    for path,rule in rules.items():
        key=canonical_path(path);value=normalize_rule(rule)
        if key in result and result[key]!=value:raise ValueError('Conflicting rules for the same executable')
        result[key]=value
    return result


@dataclass(frozen=True)
class ApplicationPolicy:
    enabled: bool
    default_profile: str
    rules: dict

    def authorize(self,application,protocol,destination):
        if protocol not in ('tcp','udp') or not isinstance(destination,str) or not destination or len(destination)>512 or '\0' in destination:
            return dict(allow=False,profile='bulk',reason='invalid_connection_context')
        try:path=canonical_path(application.get('path')) if isinstance(application,Mapping) else None
        except ValueError:path=None
        if path is None:
            return dict(allow=True,profile='bulk',reason='unverified_application')
        rule=self.rules.get(path,dict(outbound='allow',profile=self.default_profile))
        allowed=not self.enabled or rule['outbound']=='allow'
        return dict(allow=allowed,profile=PROFILES[rule['profile']],
                    reason='protection_disabled' if not self.enabled else 'application_blocked' if not allowed else 'application_allowed')

    def snapshot(self):
        return dict(enabled=self.enabled,default_profile=self.default_profile,rules={key:dict(value) for key,value in self.rules.items()},
                    scope='outbound_tunnel_connections',inbound='not_exposed')

    def digest(self):
        return hashlib.sha256(json.dumps(self.snapshot(),sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()


def PolicyEvaluator(config):
    if not isinstance(config,Mapping):raise ValueError('Invalid application policy configuration')
    enabled=config.get('protection_enabled',True);default=config.get('default_app_profile','automatic')
    if type(enabled) is not bool:raise ValueError('Protection enabled must be a boolean')
    if not isinstance(default,str) or default not in PROFILES:raise ValueError('Unknown default application profile')
    return ApplicationPolicy(enabled,default,normalize_rules(config.get('app_rules',{})))


def authorize(config,application,protocol,destination):
    """Convenience evaluator; compile PolicyEvaluator once for repeated checks."""
    return PolicyEvaluator(config).authorize(application,protocol,destination)


def save_policy_settings(*,enabled=None,default_profile=None,updates=None,remove_paths=(),config_path=CONFIG):
    path=Path(config_path)
    if path.stat().st_size>MAX_CONFIG_BYTES:raise ValueError('Configuration file exceeds its size limit')
    original=path.read_bytes();config=json.loads(original)
    rules=normalize_rules(config.get('app_rules',{}))
    for removed in remove_paths:rules.pop(canonical_path(removed),None)
    if updates:
        for key,rule in normalize_rules(updates).items():rules[key]=rule
    if len(rules)>MAX_RULES:raise ValueError('Too many application rules')
    config['app_rules']=rules
    if enabled is not None:config['protection_enabled']=enabled
    if default_profile is not None:config['default_app_profile']=default_profile
    PolicyEvaluator(config)
    encoded=json.dumps(config,indent=2)+'\n'
    if len(encoded.encode('utf-8'))>MAX_CONFIG_BYTES:raise ValueError('Configuration file exceeds its size limit')
    if path.read_bytes()!=original:raise RuntimeError('Configuration changed; try saving again')
    temporary=path.with_name(path.name+'.app-policy-'+secrets.token_hex(4))
    try:
        with temporary.open('w',encoding='utf-8') as stream:
            stream.write(encoded);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()
    return config
