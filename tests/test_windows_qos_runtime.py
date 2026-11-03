"""Use the installed NetQos enum and real Windows PowerShell parser, no policy writes."""
import base64
import json
import os
import subprocess
import unittest
from gamebond.windows_network import _POWERSHELL


@unittest.skipUnless(os.name == 'nt', 'Windows NetQos runtime')
class QosReadbackTests(unittest.TestCase):
    def test_lowercase_provider_names_match_and_cleanup_owned_policy(self):
        functions = _POWERSHELL.split("function Save-State", 1)[1].split('\ntry {', 1)[0]
        selection = next(line.strip() for line in _POWERSHELL.splitlines()
                         if '$actual = @($effective' in line)
        script = 'function Save-State' + functions + r'''
$request=@{}
$q=@{name='GameBond-CoD-0123456789abcdef01234567-0'; path='C:\Games\cod.exe'; added=$true}
$effective=@([pscustomobject]@{Name=$q.name.ToLowerInvariant(); AppPathNameMatchCondition=$q.path; DSCPAction=46; IPProtocolMatchCondition=2})
''' + selection + r'''
Assert-OwnedQos $q $actual
function Get-NetRoute { @() }
function Get-NetAdapter { @() }
function Get-NetQosPolicy { $effective }
$script:removed=@()
function Remove-NetQosPolicy { param([Parameter(ValueFromPipeline=$true)]$Policy, [switch]$Confirm) process { $script:removed += $Policy.Name } }
$s=@{routes=@(); qos=@($q); tun_index=-1; config=@{tun_name='GameBond'}}
$failures=@(Remove-Owned $s)
if ($failures.Count -ne 0 -or $script:removed.Count -ne 1 -or $q.added) { throw 'Lowercase policy was not removed' }
'''
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(script.encode('utf-16-le')).decode()],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_raw_cim_udp_enum_and_text_accept_but_wrong_match_or_action_reject(self):
        function = 'function Assert-OwnedQos' + _POWERSHELL.split('function Assert-OwnedQos', 1)[1].split('\ntry {', 1)[0]
        script = function + r'''
Import-Module NetQos -ErrorAction Stop
$q = @{name='test'; path='C:\Games\cod.exe'}
$udp = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetQosPolicy.Protocol]::UDP
if ([int]$udp -ne 2) { throw 'Installed NetQos enum differs from expected UDP=2' }
foreach ($protocol in @($udp, [uint32]$udp, 'UDP')) {
    Assert-OwnedQos $q @([pscustomobject]@{AppPathNameMatchCondition=$q.path; DSCPAction=46; IPProtocolMatchCondition=$protocol})
}
$rejected=0
foreach ($p in @(
    [pscustomobject]@{AppPathNameMatchCondition=$q.path; DSCPAction=46; IPProtocolMatchCondition=3},
    [pscustomobject]@{AppPathNameMatchCondition=$q.path; DSCPAction=0; IPProtocolMatchCondition=2},
    [pscustomobject]@{AppPathNameMatchCondition='C:\Other.exe'; DSCPAction=46; IPProtocolMatchCondition=2}
)) {
    try { Assert-OwnedQos $q @($p) } catch { $rejected++ }
}
if ($rejected -ne 3) { throw 'Invalid QoS policy was accepted' }
@{udp_enum=[int]$udp; accepted=3; rejected=$rejected} | ConvertTo-Json -Compress
'''
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(script.encode('utf-16-le')).decode()],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Native powershell.exe may emit ANSI control sequences around stdin.
        line = next(line[line.index('{'):] for line in result.stdout.splitlines() if '{"' in line)
        report = json.JSONDecoder().raw_decode(line)[0]
        self.assertEqual(report, {'udp_enum': 2, 'accepted': 3, 'rejected': 3})
