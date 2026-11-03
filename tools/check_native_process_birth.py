"""Compile and verify the native process-snapshot fallback against psutil."""
import json
import os
from pathlib import Path
import subprocess
import psutil
from build_capture_attribution import ROOT,run


def main():
    directory=ROOT/'.runtime/native-birth-test';directory.mkdir(exist_ok=True)
    header=ROOT/'.runtime/research/proxifyre/netlib/src/iphelper/gamebond_process_birth.h'
    source=directory/'probe.cpp';binary=directory/'probe.exe'
    source.write_text('#include "'+header.as_posix()+'"\n#include <iostream>\n#include <string>\n'
        'int main(int argc,char** argv) { for(int i=1;i<argc;i++) { auto pid=std::stoul(argv[i]); '
        'std::cout << pid << " " << iphelper::gamebond_snapshot_birth(pid) << "\\n"; } }\n')
    vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    installation=Path(run([str(vswhere),'-latest','-products','*','-property','installationPath']))
    vcvars=installation/'VC/Auxiliary/Build/vcvars64.bat'
    command=f'call "{vcvars}" >nul && cl.exe /nologo /EHsc /std:c++20 /Fe:"{binary}" /Fo:"{directory / "probe.obj"}" "{source}"'
    env=os.environ.copy()
    env['PATH']=str(Path(os.environ['SystemRoot'])/'System32')+';'+os.environ['SystemRoot']
    run('cmd.exe /d /s /c "'+command+'"',env=env)
    processes={os.getpid():psutil.Process()}
    for process in psutil.process_iter(['name']):
        if (process.info['name'] or '').lower() in ('svchost.exe','gwctlsrv.exe','warp-svc.exe'):
            processes[process.pid]=process
    expected={pid:p.create_time() for pid,p in processes.items()}
    output=run([str(binary),*[str(pid) for pid in expected],'0','4294967295'])
    for line in output.splitlines():
        pid,birth=map(int,line.split())
        if pid in expected:
            actual=(birth-116444736000000000)/10_000_000
            if abs(actual-expected[pid])>.001:raise RuntimeError(f'Creation time mismatch for PID {pid}')
        elif birth:raise RuntimeError('Invalid PID produced a creation time')
    report=dict(passed=True,verified_processes=len(expected),invalid_pids_rejected=True)
    (ROOT/'evidence/native-process-birth-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
