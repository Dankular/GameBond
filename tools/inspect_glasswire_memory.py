"""Read only the selected GlassWire GUI module, preserving mapped-image provenance."""
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import pefile
import psutil

ROOT=Path(__file__).resolve().parents[1]
TARGET=Path(r'C:\Program Files (x86)\GlassWire\GlassWire.exe')


def main():
    matches=[]
    for process in psutil.process_iter(['pid','exe','create_time']):
        if (process.info['exe'] or '').casefold()==str(TARGET).casefold():matches.append(process.info)
    if len(matches)!=1:raise RuntimeError('Expected one running selected GlassWire GUI')
    process=matches[0]
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];api.OpenProcess.restype=wintypes.HANDLE
    api.CloseHandle.argtypes=[wintypes.HANDLE]
    api.K32EnumProcessModulesEx.argtypes=[wintypes.HANDLE,ctypes.POINTER(ctypes.c_void_p),wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.DWORD]
    api.K32GetModuleFileNameExW.argtypes=[wintypes.HANDLE,ctypes.c_void_p,wintypes.LPWSTR,wintypes.DWORD]
    api.ReadProcessMemory.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    handle=api.OpenProcess(0x410,False,process['pid'])
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    try:
        modules=(ctypes.c_void_p*2048)();needed=wintypes.DWORD()
        if not api.K32EnumProcessModulesEx(handle,modules,ctypes.sizeof(modules),ctypes.byref(needed),3):raise ctypes.WinError(ctypes.get_last_error())
        inventory=[]
        for base in modules[:needed.value//ctypes.sizeof(ctypes.c_void_p)]:
            name=ctypes.create_unicode_buffer(32768)
            if api.K32GetModuleFileNameExW(handle,base,name,len(name)):inventory.append(dict(base=base,path=name.value))
        module=next(m for m in inventory if m['path'].casefold()==str(TARGET).casefold())
        original=TARGET.read_bytes();pe=pefile.PE(data=original)
        size=pe.OPTIONAL_HEADER.SizeOfImage
        if size>128*1024*1024:raise RuntimeError('Unexpected mapped image size')
        image=bytearray(size);gaps=[]
        for offset in range(0,size,4096):
            length=min(4096,size-offset);buffer=ctypes.create_string_buffer(length);read=ctypes.c_size_t()
            if api.ReadProcessMemory(handle,module['base']+offset,buffer,length,ctypes.byref(read)):
                image[offset:offset+read.value]=buffer.raw[:read.value]
            else:gaps.append(dict(rva=offset,bytes=length,error=ctypes.get_last_error()))
        directory=ROOT/'.runtime/research/glasswire';directory.mkdir(parents=True,exist_ok=True)
        mapped=directory/'GlassWire.mapped.bin';mapped.write_bytes(image)
        memory_pe=pefile.PE(data=bytes(image))
        memory_pe.OPTIONAL_HEADER.ImageBase=module['base']
        for section in memory_pe.sections:
            section.PointerToRawData=section.VirtualAddress
            section.SizeOfRawData=min((section.Misc_VirtualSize+511)//512*512,len(image)-section.VirtualAddress)
        memory_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress=0
        memory_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size=0
        derived=directory/'GlassWire.mapped-layout.exe';memory_pe.write(str(derived))
        record=dict(target=str(TARGET),source_sha256=hashlib.sha256(original).hexdigest(),pid=process['pid'],process_created=process['create_time'],
                    base=module['base'],mapped_bytes=size,mapped_sha256=hashlib.sha256(image).hexdigest(),
                    unmapped_pages=gaps,modules=inventory,derived_pe=str(derived),derived_sha256=hashlib.sha256(derived.read_bytes()).hexdigest(),
                    method='OpenProcess QUERY_INFORMATION|VM_READ and ReadProcessMemory, selected GUI module only; no target writes, hooks or code execution',
                    limitations=['Unmapped/unreadable pages are zero-filled and listed','Derived PE uses mapped section offsets; original on-disk imports and layout are not restored','This snapshot contains loaded memory, not original source'])
        (ROOT/'evidence/glasswire/memory-provenance.json').write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps(dict(pid=process['pid'],base=hex(module['base']),bytes=size,unreadable_pages=len(gaps),derived=str(derived))))
    finally:api.CloseHandle(handle)


if __name__=='__main__':main()
