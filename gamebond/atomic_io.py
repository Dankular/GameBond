"""Bounded atomic state I/O, including Windows readers that permit replacement."""
import json
import os
from pathlib import Path
import time

def _replace_once(source,destination):
    if os.name=='nt' and Path(destination).exists():
        import ctypes
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        call=api.ReplaceFileW
        call.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_void_p]
        call.restype=ctypes.c_int
        if call(str(destination),str(source),None,0,None,None):return
        error=ctypes.get_last_error()
        if error!=2:raise ctypes.WinError(error)
    os.replace(source,destination)

def replace_file(source,destination,*,timeout=1.5):
    deadline=time.monotonic()+timeout
    delay=.005
    while True:
        try:
            _replace_once(source,destination);return
        except OSError as exc:
            if os.name!='nt' or getattr(exc,'winerror',None) not in (5,32,33) or time.monotonic()>=deadline:raise
            time.sleep(min(delay,max(0,deadline-time.monotonic())));delay=min(.05,delay*2)

def read_bytes_shared(path,limit=4*1024*1024):
    """FILE_SHARE_DELETE prevents our polling readers from blocking atomic rename."""
    if os.name=='nt':
        import ctypes
        from ctypes import wintypes
        import msvcrt
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        call=api.CreateFileW
        call.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        call.restype=wintypes.HANDLE
        handle=call(str(Path(path).resolve()),0x80000000,7,None,3,0x80,None)
        if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        try:descriptor=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        except BaseException:
            api.CloseHandle.argtypes=[wintypes.HANDLE];api.CloseHandle(handle);raise
        stream=os.fdopen(descriptor,'rb')
    else:stream=Path(path).open('rb')
    with stream:data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('State file exceeds its size limit')
    return data

def read_json_shared(path,limit=4*1024*1024):
    return json.loads(read_bytes_shared(path,limit).decode('utf-8-sig'))
