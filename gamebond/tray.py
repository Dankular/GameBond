"""Windows tray controls; callbacks queue actions for the Tk main thread."""
import ctypes
import hashlib
import os


class AgentLease:
    """One tray agent per workspace; another launch requests Show instead."""
    def __init__(self, root):
        from ctypes import wintypes
        self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.api.CreateMutexW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.LPCWSTR]
        self.api.CreateMutexW.restype=wintypes.HANDLE
        self.api.CreateEventW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.BOOL,wintypes.LPCWSTR]
        self.api.CreateEventW.restype=wintypes.HANDLE
        self.api.SetEvent.argtypes=[wintypes.HANDLE]
        self.api.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        self.api.CloseHandle.argtypes=[wintypes.HANDLE]
        name='Local\\GameBond.Widget.'+hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()[:16]
        self.event=self.api.CreateEventW(None,False,False,name+'.Show')
        if not self.event:raise ctypes.WinError(ctypes.get_last_error())
        self.mutex=self.api.CreateMutexW(None,False,name)
        error=ctypes.get_last_error()
        if not self.mutex:
            self.api.CloseHandle(self.event);raise ctypes.WinError(error)
        self.owner=error!=183  # ERROR_ALREADY_EXISTS
        if not self.owner:self.api.SetEvent(self.event)

    def show_requested(self):
        return self.api.WaitForSingleObject(self.event,0)==0

    def close(self):
        for name in ('event','mutex'):
            handle=getattr(self,name,None)
            if handle:self.api.CloseHandle(handle);setattr(self,name,None)


class TrayAgent:
    def __init__(self,dispatch):
        import pystray
        from PIL import Image, ImageDraw
        self.dispatch=dispatch;self.state=('idle',False,0,0,False);self.flash_on=False
        self.images={}
        for name,color in (('idle','#000000'),('connected','#00c853'),('busy','#f2be70')):
            image=Image.new('RGBA',(64,64),(0,0,0,0));draw=ImageDraw.Draw(image)
            draw.rounded_rectangle((2,2,62,62),radius=14,fill=color)
            draw.line([(12,47),(27,17),(38,36),(53,11)],fill='#ffffff',width=6)
            self.images[name]=image
        item=pystray.MenuItem
        def action(name):return lambda icon,entry:dispatch(name)
        self.icon=pystray.Icon('GameBond',self.images['idle'],'GameBond · Disconnected',menu=pystray.Menu(
            item('Show GameBond',action('show'),default=True),
            item(lambda entry:'Disconnect' if self.state[0]=='running' else 'Connect',action('toggle'),
                 enabled=lambda entry:not self.state[1]),
            pystray.Menu.SEPARATOR,
            item('Manage apps',action('apps')),item('Network settings',action('networks')),
            item('Link roles & limits',action('links')),
            pystray.Menu.SEPARATOR,item('Quit (stop tunnel)',action('quit'))))
        self.icon.run_detached()

    @property
    def visible(self):return self.icon.visible

    def update(self,runtime,busy=False,problem=None):
        paths=[p for p in runtime.get('transport',{}).get('paths',[]) if p.get('enabled',True)] if runtime else []
        healthy=sum(bool(p.get('healthy')) for p in paths)
        state=runtime.get('state','idle') if runtime else 'idle'
        issue=bool(problem) or state=='failed' or (state=='running' and (not paths or healthy<len(paths)))
        snapshot=(state,busy or state in ('starting','connecting','restarting','stopping'),healthy,len(paths),issue)
        if snapshot==self.state and not issue:return
        self.state=snapshot
        if issue:
            self.flash_on=not self.flash_on
            color='busy' if self.flash_on else 'idle'
        else:
            self.flash_on=False
            color='connected' if state=='running' and healthy else 'busy' if snapshot[1] else 'idle'
        self.icon.icon=self.images[color]
        self.icon.title=(f'GameBond · Network problem · {healthy}/{len(paths)} links' if issue else
                         f'GameBond · {healthy}/{len(paths)} links · {runtime["peer"][0]}' if state=='running'
                         else 'GameBond · '+('Connecting…' if busy else state.capitalize()))
        self.icon.update_menu()

    def close(self):self.icon.stop()
