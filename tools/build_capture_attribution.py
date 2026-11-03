"""Build the identity-preserving capture DLL in the workspace; never install it."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PROXIFYRE_COMMIT='5e3bc845d73a47a0931b1233c745580cb916f4ba'
GSL_COMMIT='a4651c0f995d3309432f78e977058d9d4760f9fa'
HIDDEN=getattr(subprocess,'CREATE_NO_WINDOW',0)


def run(args,*,cwd=ROOT,env=None):
    result=subprocess.run(args,cwd=cwd,env=env,capture_output=True,text=True,creationflags=HIDDEN)
    if result.returncode:raise RuntimeError(result.stderr or result.stdout)
    return result.stdout.strip()


def checkout(path,url,commit):
    if not path.exists():
        run(['git','clone','--no-checkout',url,str(path)])
        run(['git','checkout','--detach',commit],cwd=path)
    if run(['git','rev-parse','HEAD'],cwd=path)!=commit:raise RuntimeError(f'Unexpected source revision: {path}')


def main():
    if os.name!='nt':raise RuntimeError('Capture extension build requires Windows C++/CLI tools')
    research=ROOT/'.runtime/research';research.mkdir(parents=True,exist_ok=True)
    source=research/'proxifyre';gsl=research/'GSL'
    checkout(source,'https://github.com/wiresock/proxifyre.git',PROXIFYRE_COMMIT)
    checkout(gsl,'https://github.com/microsoft/GSL.git',GSL_COMMIT)
    patch=ROOT/'tools/native_capture_attribution.patch'
    check=subprocess.run(['git','apply','--check',str(patch)],cwd=source,capture_output=True,creationflags=HIDDEN)
    if check.returncode:
        run(['git','apply','--reverse','--check',str(patch)],cwd=source)
    else:run(['git','apply',str(patch)],cwd=source)
    vswhere=Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
    installation=run([str(vswhere),'-latest','-products','*','-property','installationPath'])
    msbuild=Path(installation)/'MSBuild/Current/Bin/MSBuild.exe'
    packages=Path(os.environ.get('GAMEBOND_BOOST_PACKAGES','D:/vcpkg/packages'))
    boost=[path/'include' for path in sorted(packages.glob('boost-*_x64-windows')) if (path/'include').is_dir()]
    if not any((path/'boost/pool/object_pool.hpp').exists() for path in boost):
        raise RuntimeError('Existing Boost.Pool headers are required; set GAMEBOND_BOOST_PACKAGES to a vcpkg packages directory')
    env=os.environ.copy();env['CL']=' '.join('/I"'+str(path)+'"' for path in [gsl/'include',*boost])
    common=['/p:Configuration=Release','/p:Platform=x64','/p:SolutionDir='+str(source)+'\\','/verbosity:minimal','/nologo']
    run([str(msbuild),str(source/'ndisapi.lib/ndisapilib.vcxproj'),*common],env=env)
    print('NDIS API static library built',flush=True)
    run([str(msbuild),str(source/'socksify/socksify.vcxproj'),*common],env=env)
    output=ROOT/'build/native-capture';output.mkdir(parents=True,exist_ok=True)
    target=output/'socksify.dll';shutil.copy2(source/'bin/dll/x64/Release/socksify.dll',target)
    for name in ('LICENSE','COPYING','README.md'):
        if (source/name).exists():shutil.copy2(source/name,output/name)
    manifest=dict(schema=1,feature='gamebond-owner-v1',source_url='https://github.com/wiresock/proxifyre',
                  source_commit=PROXIFYRE_COMMIT,gsl_commit=GSL_COMMIT,architecture='x64',
                  patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),
                  dll_sha256=hashlib.sha256(target.read_bytes()).hexdigest())
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest),flush=True)


if __name__=='__main__':main()
