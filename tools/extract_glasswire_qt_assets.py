"""Extract Qt resources from a read-only snapshot, using observed registry pointers.

The Qt 5.15.2 x86 registry layout is established by qRegisterResourceData
disassembly and qtbase/v5.15.2/src/corelib/io/qresource.cpp. No target writes.
"""
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import zlib

ROOT=Path(__file__).resolve().parents[1]


def main():
    provenance=json.loads((ROOT/'evidence/glasswire/memory-provenance.json').read_text())
    modules=json.loads((ROOT/'evidence/glasswire/module-inventory.json').read_text())
    qt=next(m for m in modules if m['path'].lower().endswith('qt5core.dll'))
    snapshot=(ROOT/'.runtime/research/glasswire/GlassWire.mapped.bin').read_bytes();base=provenance['base']
    if hashlib.sha256(snapshot).hexdigest()!=provenance['mapped_sha256']:raise ValueError('Snapshot changed')
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];api.OpenProcess.restype=wintypes.HANDLE
    api.ReadProcessMemory.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    api.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=api.OpenProcess(0x410,False,provenance['pid'])
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    def live(address,size):
        if not 0<size<=16384:raise ValueError('Unexpected registry read size')
        buffer=ctypes.create_string_buffer(size);read=ctypes.c_size_t()
        if not api.ReadProcessMemory(handle,address,buffer,size,ctypes.byref(read)) or read.value!=size:raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw
    def image(address,size):
        offset=address-base
        if offset<0 or size<0 or offset+size>len(snapshot):raise ValueError('Resource outside selected image snapshot')
        return snapshot[offset:offset+size]
    records=[];registries=[];total=0
    output=ROOT/'assets/glasswire';output.mkdir(parents=True,exist_ok=True)
    try:
        # x86 QResourceGlobalData::resourceList in the verified installed Qt DLL.
        list_pointer=struct.unpack('<I',live(qt['base']+0x4bc070,4))[0]
        reference,allocated,begin,end=struct.unpack('<4i',live(list_pointer,16))
        if not 0<=begin<=end<=allocated<=1024:raise ValueError('Unexpected resource-list bounds')
        root_bytes=live(list_pointer+16+begin*4,(end-begin)*4)
        for root in struct.unpack('<'+'I'*(end-begin),root_bytes):
            vtable,tree,names,data,version,references=struct.unpack('<6I',live(root,24))
            if not all(base<=a<base+len(snapshot) for a in (tree,names,data)):continue
            if version not in (1,2,3):raise ValueError('Unsupported Qt resource version')
            registries.append(dict(root=root,tree=tree,names=names,data=data,version=version))
            stride=22 if version>=2 else 14;visited=set()
            def node(index,parent=''):
                nonlocal total
                if index in visited or len(visited)>=16384:raise ValueError('Cyclic or oversized resource tree')
                visited.add(index);raw=image(tree+index*stride,stride)
                name_offset,flags=struct.unpack_from('>IH',raw)
                if index:
                    length=struct.unpack('>H',image(names+name_offset,2))[0]
                    if length>1024:raise ValueError('Oversized resource name')
                    name=image(names+name_offset+6,length*2).decode('utf-16-be')
                    path=PurePosixPath(parent)/name
                    if path.is_absolute() or any(part in ('..','.') for part in path.parts) or ':' in str(path):raise ValueError('Unsafe resource path')
                else:path=PurePosixPath()
                if flags&2:
                    count,first=struct.unpack_from('>II',raw,6)
                    if count>16384:raise ValueError('Oversized directory')
                    for child in range(first,first+count):node(child,str(path))
                    return
                offset=struct.unpack_from('>I',raw,10)[0]
                size=struct.unpack('>I',image(data+offset,4))[0]
                if size>16*1024*1024:raise ValueError('Oversized asset')
                payload=image(data+offset+4,size)
                if flags&1:
                    expected=struct.unpack('>I',payload[:4])[0]
                    if expected>16*1024*1024:raise ValueError('Oversized decompressed asset')
                    payload=zlib.decompress(payload[4:])
                    if len(payload)!=expected:raise ValueError('Qt zlib length mismatch')
                elif flags&4:
                    import zstandard
                    payload=zstandard.ZstdDecompressor().decompress(payload,max_output_size=16*1024*1024)
                total+=len(payload)
                if total>128*1024*1024:raise ValueError('Asset extraction budget exceeded')
                destination=output/str(path)
                digest=hashlib.sha256(payload).hexdigest()
                if destination.exists() and hashlib.sha256(destination.read_bytes()).hexdigest()!=digest:
                    destination=destination.with_name(destination.stem+'-'+digest[:8]+destination.suffix)
                destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(payload)
                records.append(dict(resource=':/'+str(path),output=str(destination.relative_to(ROOT)),bytes=len(payload),sha256=digest,
                                    registry=len(registries)-1,node=index,flags=flags,payload_address=data+offset+4,stored_bytes=size))
            node(0)
        if live(list_pointer+16+begin*4,len(root_bytes))!=root_bytes:raise ValueError('Resource registry changed during extraction')
    finally:api.CloseHandle(handle)
    manifest=dict(source=provenance,qt_module=qt,method='Read-only Qt registry pointers plus immutable selected-module snapshot; no hooks or target calls',
                  registries=registries,resources=records,total_bytes=total,
                  limitations=['Only resources backed by selected GUI module extracted','Runtime-selected theme, fonts, layout and widget behavior require further observation'])
    (ROOT/'evidence/glasswire/qt-assets.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(dict(assets=len(records),registries=len(registries),bytes=total,extensions=sorted({Path(r['output']).suffix for r in records}))))


if __name__=='__main__':main()
