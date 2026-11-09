"""Compact native Windows link dashboard. Runs without elevation."""
from __future__ import annotations
from collections import deque
import ctypes
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, filedialog

from .widget_data import CONFIG, ROOT, Monitor, human_bytes, save_selection, save_applications, TunnelRateSampler, save_link_policies
from .userspace import live_status, request_stop, STATUS
from .link_limits import MIN_LINKS,MAX_LINKS

BG='#0c1220'; CARD='#151e30'; BORDER='#253149'; TEXT='#eef4ff'
MUTED='#91a0b8'; CYAN='#4bdfce'; BLUE='#8b9dff'; AMBER='#f2be70'


def label(parent,text='',size=10,color=TEXT,bold=False,**kwargs):
    return tk.Label(parent,text=text,font=('Segoe UI',size,'bold' if bold else 'normal'),
                    fg=color,bg=parent['bg'],**kwargs)

def button(parent,text,command,primary=False):
    return tk.Button(parent,text=text,command=command,font=('Segoe UI',10,'bold'),
                     bg=CYAN if primary else BORDER,fg=BG if primary else TEXT,
                     activebackground='#65e8d9' if primary else '#34435f',
                     activeforeground=BG if primary else TEXT,borderwidth=0,
                     highlightthickness=0,padx=15,pady=9,cursor='hand2')


class Chart(tk.Canvas):
    def __init__(self,parent,height=115):
        super().__init__(parent,height=height,bg=CARD,highlightthickness=0)
        self.samples=deque([(0,0)]*60,maxlen=60)
        self.bind('<Configure>',lambda _:self.draw())

    def draw(self,sample=None):
        if sample is not None: self.samples.append(sample)
        self.delete('all')
        w,h=self.winfo_width(),self.winfo_height()
        if w<20:return
        top,bottom=18,h-20
        ceiling=max(.1,max(max(s) for s in self.samples)*1.2)
        for fraction in (0,.5,1):
            y=top+(bottom-top)*fraction
            self.create_line(0,y,w,y,fill=BORDER,dash=(2,5))
        self.create_text(w-2,4,text=f'{ceiling:.1f} Mbps',fill=MUTED,anchor='ne',font=('Segoe UI',8))
        for index,color in ((1,BLUE),(0,CYAN)):
            points=[]
            for i,sample in enumerate(self.samples):
                points.extend([i*w/59,bottom-sample[index]/ceiling*(bottom-top)])
            self.create_polygon([0,bottom]+points+[w,bottom],fill='#1c3544' if index==0 else '#242d49',outline='')
            self.create_line(*points,fill=color,width=2,smooth=True)
        self.create_text(0,h-2,text='60 seconds ago',fill=MUTED,anchor='sw',font=('Segoe UI',8))
        self.create_text(w,h-2,text='Now',fill=MUTED,anchor='se',font=('Segoe UI',8))


class LinkCard(tk.Frame):
    def __init__(self,parent):
        super().__init__(parent,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
        self.name=label(self,size=13,bold=True);self.name.pack(anchor='w',padx=16,pady=(14,1))
        self.device=label(self,size=9,color=MUTED);self.device.pack(anchor='w',padx=16)
        self.status=label(self,size=9,color=CYAN);self.status.pack(anchor='w',padx=16,pady=(8,2))
        row=tk.Frame(self,bg=CARD);row.pack(fill='x',padx=16,pady=(5,1))
        self.down=label(row,size=15,bold=True,color=CYAN);self.down.pack(side='left')
        self.up=label(row,size=11,color=BLUE);self.up.pack(side='right')
        self.detail=label(self,size=9,color=MUTED);self.detail.pack(anchor='w',padx=16,pady=(4,14))

    def update_link(self,link,rate,nickname,path):
        self.name.config(text=nickname)
        self.device.config(text=link['name'] if link else 'Adapter unavailable')
        up=link and link['up']
        if path and not path.get('enabled',True):status,color='●  Disabled by link policy',MUTED
        elif path:status,color=('●  Connected',CYAN) if path.get('healthy') else ('●  Reconnecting',AMBER)
        else:status,color=('●  Available',CYAN) if up else ('●  Disconnected',AMBER)
        self.status.config(text=status,fg=color)
        self.down.config(text=f"↓ {rate.get('down',0)*8/1e6:.2f}")
        self.up.config(text=f"↑ {rate.get('up',0)*8/1e6:.2f} Mbps")
        rtt=path.get('rtt_ms') if path else None
        address=link['addresses'][0] if link and link['addresses'] else 'No IPv4'
        quality=(f"{rtt:.0f} ms · jitter {path.get('rtt_jitter_ms',0):.0f} ms" if rtt is not None else 'Latency —')
        self.detail.config(text=f'{address}\n{quality}')


class Widget:
    def __init__(self,root,lease=None):
        self.root=root
        self.lease=lease;self.tray=None;self.quitting=False;self.tray_error=None;self.verifying=False;self.exit_pid=None
        root.title('GameBond · Link monitor')
        work_height=root.winfo_screenheight()
        if os.name=='nt':
            from ctypes import wintypes
            area=wintypes.RECT()
            if ctypes.windll.user32.SystemParametersInfoW(48,0,ctypes.byref(area),0):work_height=area.bottom-area.top
        height=min(760,max(480,work_height-100))
        root.geometry(f'620x{height}');root.minsize(540,min(540,height))
        root.configure(bg=BG)
        self.monitor=Monitor();self.events=queue.SimpleQueue();self.testing=False;self.tunnel_rates=TunnelRateSampler()
        self.backend=None;self.connect_pending=False
        self.last_runtime_state=None;self.connect_started=None
        self.config=json.loads(CONFIG.read_text())
        self.previous_selection=tuple(self.config.get('interface_indices',[]))
        self.closed=False
        self._build()
        if os.name=='nt':
            from .tray import TrayAgent
            try:self.tray=TrayAgent(lambda action:self.events.put(('tray',action)))
            except Exception as exc:self.notice.config(text=f'Tray unavailable: {exc}',fg=AMBER)
        root.protocol('WM_DELETE_WINDOW',self.close)
        root.after(100,self.tick)

    def _build(self):
        shell=tk.Frame(self.root,bg=BG);shell.pack(fill='both',expand=True,padx=18,pady=14)
        bottom=tk.Frame(shell,bg=BG);bottom.pack(side='bottom',fill='x',pady=(8,0))
        self.notice=label(bottom,'Detecting physical links…',9,MUTED,wraplength=560,justify='left')
        self.notice.pack(fill='x',pady=(0,8))
        self.bottom=bottom
        scroll=tk.Scrollbar(shell,orient='vertical',width=10,bg=CARD,troughcolor=BG,activebackground=BORDER)
        scroll.pack(side='right',fill='y')
        canvas=tk.Canvas(shell,bg=BG,highlightthickness=0,yscrollcommand=scroll.set)
        canvas.pack(side='left',fill='both',expand=True);scroll.config(command=canvas.yview)
        body=tk.Frame(canvas,bg=BG)
        window=canvas.create_window((0,0),window=body,anchor='nw')
        body.bind('<Configure>',lambda _:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda event:canvas.itemconfigure(window,width=event.width))
        def wheel(event):
            if event.widget.winfo_toplevel()==self.root and body.winfo_reqheight()>canvas.winfo_height():
                canvas.yview_scroll(-int(event.delta/120),'units')
        self.root.bind_all('<MouseWheel>',wheel)
        top=tk.Frame(body,bg=BG);top.pack(fill='x')
        mark=tk.Canvas(top,width=30,height=28,bg=BG,highlightthickness=0);mark.pack(side='left',padx=(0,9))
        mark.create_line(3,23,12,6,18,16,27,1,fill=CYAN,width=3)
        label(top,'GAMEBOND',17,bold=True).pack(side='left')
        self.pin=tk.BooleanVar()
        tk.Checkbutton(top,text='Keep on top',variable=self.pin,command=lambda:self.root.attributes('-topmost',self.pin.get()),
                       bg=BG,fg=MUTED,selectcolor=CARD,activebackground=BG,activeforeground=TEXT,
                       font=('Segoe UI',9),borderwidth=0).pack(side='right')
        label(body,'Two links. One view.',10,MUTED).pack(anchor='w',pady=(4,19))
        header=tk.Frame(body,bg=BG);header.pack(fill='x',pady=(0,10))
        label(header,'LIVE TRAFFIC',9,MUTED,True).pack(side='left')
        self.badge=label(header,'●  Tunnel idle',9,MUTED);self.badge.pack(side='right')
        traffic=tk.Frame(body,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
        traffic.pack(fill='x')
        numbers=tk.Frame(traffic,bg=CARD);numbers.pack(fill='x',padx=20,pady=(17,0))
        for column in range(2):numbers.columnconfigure(column,weight=1)
        label(numbers,'↓  DOWNLOAD',9,CYAN,True).grid(row=0,column=0,sticky='w')
        label(numbers,'↑  UPLOAD',9,BLUE,True).grid(row=0,column=1,sticky='w')
        self.download=label(numbers,'0.00',32,bold=True);self.download.grid(row=1,column=0,sticky='w')
        self.upload=label(numbers,'0.00',32,bold=True);self.upload.grid(row=1,column=1,sticky='w')
        label(numbers,'Mbps',9,MUTED).grid(row=2,column=0,sticky='w')
        label(numbers,'Mbps',9,MUTED).grid(row=2,column=1,sticky='w')
        self.chart=Chart(traffic);self.chart.pack(fill='x',padx=20,pady=(6,5))
        self.traffic_source=label(traffic,'Waiting for application throughput',9,MUTED,wraplength=530,justify='left')
        self.traffic_source.pack(anchor='w',padx=20,pady=(0,6))
        self.transport_detail=label(traffic,'',9,MUTED,wraplength=530,justify='left')
        self.transport_detail.pack(anchor='w',padx=20,pady=(0,13))
        linkshead=tk.Frame(body,bg=BG);linkshead.pack(fill='x',pady=(18,8))
        self.links_title=label(linkshead,'YOUR LINKS',9,MUTED,True);self.links_title.pack(side='left')
        change=tk.Label(linkshead,text='Select networks  ›',fg=CYAN,bg=BG,font=('Segoe UI',9,'bold'),cursor='hand2')
        change.pack(side='right');change.bind('<Button-1>',lambda _:self.networks())
        cards=tk.Frame(body,bg=BG);cards.pack(fill='x')
        cards.columnconfigure(0,weight=1,uniform='link');cards.columnconfigure(1,weight=1,uniform='link')
        self.linkcards_frame=cards;self.linkcards=[];self._ensure_linkcards()
        button(body,'Link roles & limits',self.link_controls).pack(anchor='e',pady=(6,0))
        server=tk.Frame(body,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
        server.pack(fill='x',pady=(14,0))
        left=tk.Frame(server,bg=CARD);left.pack(side='left',padx=16,pady=12)
        label(left,'YOUR VPS',8,MUTED,True).pack(anchor='w')
        label(left,self.config['peer'][0],12,bold=True).pack(anchor='w',pady=(2,0))
        self.tunnel=label(server,'No tunnel running',10,MUTED);self.tunnel.pack(side='right',padx=16)
        exitrow=tk.Frame(body,bg=BG);exitrow.pack(fill='x',pady=(7,0))
        self.exit_check=button(exitrow,'Verify exit IP',self.verify_exit);self.exit_check.pack(side='right')
        self.exit_result=label(exitrow,'Exit IP not yet verified',9,MUTED,wraplength=370,justify='left')
        self.exit_result.pack(side='left',fill='x',expand=True)
        apps=tk.Frame(body,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
        apps.pack(fill='x',pady=(12,0))
        button(apps,'Manage apps',self.applications).pack(side='right',padx=12,pady=12)
        self.app_scope=label(apps,'',10,TEXT,wraplength=350,justify='left')
        self.app_scope.pack(side='left',fill='x',expand=True,padx=16,pady=12)
        usage=tk.Frame(body,bg=BG);usage.pack(fill='x',pady=(13,0))
        self.usage=label(usage,'0 B received  ·  0 B sent',9,MUTED);self.usage.pack(side='left')
        label(usage,'Since opening',8,MUTED).pack(side='right')
        footer=tk.Frame(self.bottom,bg=BG);footer.pack(fill='x')
        self.connect=button(footer,'Connect',self.toggle_tunnel,True);self.connect.pack(side='left',padx=(0,8))
        self.check=button(footer,'Check VPS',self.test);self.check.pack(side='left')
        button(footer,'Network settings',self.networks).pack(side='right')

    def tick(self):
        if self.closed:return
        data=self.monitor.snapshot()
        selected=self.config.get('interface_indices',[])
        links=[next((r for r in data['links'] if r['index']==i),None) for i in selected]
        rates=[data['rates'].get(r['name'],{}) if r else {} for r in links]
        down=sum(r.get('down',0) for r in rates)*8/1e6
        up=sum(r.get('up',0) for r in rates)*8/1e6
        telemetry=data['telemetry']
        paths=telemetry.get('transport',{}).get('paths',[]) if telemetry else []
        enabled_paths=[p for p in paths if p.get('enabled',True)]
        healthy=sum(bool(p.get('healthy')) for p in enabled_paths)
        runtime=live_status()
        if not runtime and self.last_runtime_state in ('running','starting','connecting'):
            try:
                previous=json.loads(STATUS.read_text())
                if previous.get('state') not in ('stopped','stopping'):
                    self.tray_error=previous.get('error') or 'Tunnel stopped reporting status'
            except (OSError,ValueError):self.tray_error='Tunnel stopped reporting status'
        self.exit_check.config(state='normal' if runtime and runtime['state']=='running' and not self.verifying else 'disabled')
        if self.exit_pid is not None and (not runtime or runtime['pid']!=self.exit_pid):
            self.exit_pid=None;self.exit_result.config(text='Exit IP not yet verified',fg=MUTED)
        tunnel_rates=self.tunnel_rates.sample(runtime,time.monotonic())
        application=tunnel_rates['application'];encrypted=tunnel_rates['encrypted']
        measured=application or tunnel_rates['ip']
        self.download.config(text=f"{measured['down']*8/1e6:.2f}" if measured else '—')
        self.upload.config(text=f"{measured['up']*8/1e6:.2f}" if measured else '—')
        self.chart.draw((measured['down']*8/1e6,measured['up']*8/1e6) if measured else (0,0))
        self.traffic_source.config(text='Application payload through VPS · excludes tunnel retransmissions and duplicate copies' if application else
                                  'Tunnel IP throughput · includes inner headers and retransmissions' if runtime else 'No active tunnel')
        transport=runtime.get('transport',{}) if runtime else {}
        wire=(f"Encrypted tunnel ↓ {encrypted['down']*8/1e6:.2f} / ↑ {encrypted['up']*8/1e6:.2f} Mbps" if encrypted else 'Encrypted tunnel idle')
        self.transport_detail.config(text=f"{wire}\nAdapters ↓ {down:.2f} / ↑ {up:.2f} Mbps · repairs {transport.get('repair_packets',0)} · duplicate copies received {transport.get('duplicate_copies',0)}")
        if self.lease and self.lease.show_requested():self.show()
        if runtime:self.tray_error=None
        if self.tray:self.tray.update(runtime,self.connect_pending or self.testing,self.tray_error or data['error'])
        if self.quitting and not runtime and not self.connect_pending:
            self.finish_quit();return
        mode=self.config.get('capture_mode','all')
        summary='All apps · IPv4 through VPS' if mode=='all' else f"Selected apps through VPS: {len(self.config.get('cod_executables',[]))}"
        if runtime and (runtime.get('capture_mode','selected')!=mode or
                runtime.get('captured_apps',self.config.get('cod_executables',[]))!=self.config.get('cod_executables',[])):
            summary+=' · reconnect to apply'
        self.app_scope.config(text=summary)
        if self.backend is not None and self.backend.poll() is not None:
            if self.backend.returncode:
                try:
                    record=json.loads((ROOT/'.runtime/userspace-start-error.json').read_text())
                    reason=record.get('error') if record.get('pid')==self.backend.pid else None
                except (OSError,ValueError):reason=None
                self.notice.config(text=reason or 'Tunnel could not start. See .runtime/userspace.log',fg=AMBER)
                self.tray_error=reason or 'Tunnel could not start'
            self.backend=None;self.connect_pending=False
        if runtime:
            state=runtime['state'];self.connect_pending=False
            if state=='running' and self.last_runtime_state!='running':
                self.notice.config(text=f"Connected to your VPS · {self.config['peer'][0]}",fg=CYAN)
                self.connect_started=None
            self.connect.config(text='Disconnect' if state=='running' else state.capitalize()+'…',
                                state='normal' if state=='running' else 'disabled')
        elif not self.connect_pending:self.connect.config(text='Connect',state='normal')
        self.last_runtime_state=runtime['state'] if runtime else None
        if self.connect_started and time.monotonic()-self.connect_started>30:
            if runtime:request_stop()
            elif self.backend and self.backend.poll() is None:self.backend.terminate()
            self.connect_started=None;self.connect_pending=False
            self.notice.config(text='Connection timed out. Check both selected links and your VPS.',fg=AMBER)
        self.check.config(state='disabled' if runtime or self.connect_pending or self.testing else 'normal')
        if telemetry:
            self.badge.config(text=f'●  {healthy}/{len(enabled_paths)} enabled tunnel paths',fg=CYAN if healthy and healthy==len(enabled_paths) else AMBER)
            self.tunnel.config(text='Connected' if healthy and healthy==len(enabled_paths) else f'Connected · {healthy} link' if healthy else 'Reconnecting…',fg=CYAN if healthy and healthy==len(enabled_paths) else AMBER)
        else:
            connecting=runtime and runtime['state'] in ('starting','connecting')
            text='●  Connecting to VPS' if connecting else '●  Waiting for telemetry' if data['telemetry_stale'] else '●  Tunnel idle'
            self.badge.config(text=text,fg=MUTED)
            self.tunnel.config(text='Connecting…' if connecting else 'No live tunnel telemetry' if data['telemetry_stale'] else 'No tunnel running',fg=MUTED)
        self._ensure_linkcards()
        for i,card in enumerate(self.linkcards):
            link=links[i] if i<len(links) else None
            path=next((p for p in paths if p.get('interface_index')==selected[i]),None) if i<len(selected) else None
            nickname=('5G · iPhone' if link and 'Apple' in link['description'] else
                      'Starlink' if i==0 and link and link['name']=='Ethernet' else link['name'] if link else f'Link {i+1}')
            card.update_link(link,rates[i] if i<len(rates) else {},nickname,path)
        active=sum(bool(r and r['up']) for r in links)
        self.links_title.config(text=f'YOUR LINKS  ·  {active}/{len(selected)} AVAILABLE')
        received=sum(r.get('received',0) for r in rates);sent=sum(r.get('sent',0) for r in rates)
        self.usage.config(text=f'{human_bytes(received)} received  ·  {human_bytes(sent)} sent')
        if data['error']:self.notice.config(text=data['error'],fg=AMBER)
        elif self.notice['text']=='Detecting physical links…' and data['links']:
            self.notice.config(text='Live adapter counters · settings apply on the next connection',fg=MUTED)
        while not self.events.empty():
            kind,payload=self.events.get()
            if kind=='selection':
                self.config=payload;self.chart.samples=deque([(0,0)]*60,maxlen=60)
                self.notice.config(text='Network selection saved for the next connection.',fg=CYAN)
            elif kind=='error':
                self.quitting=False
                self.tray_error=payload
                self.testing=False;self.check.config(state='normal',text='Check VPS')
                self.notice.config(text=payload,fg=AMBER)
            elif kind=='tested':
                self.testing=False;self.check.config(state='normal',text='Check VPS')
                rtt=payload['netstack'].get('udp_rtt_ms',{})
                self.notice.config(text=f"VPS check passed · UDP p95 {rtt.get('p95',0):.1f} ms · both links verified",fg=CYAN)
            elif kind=='started':
                self.backend=payload
            elif kind=='stopped':
                self.tray_error=None
                self.connect_pending=False
                self.notice.config(text='Tunnel stopped. Your adapters and routes are unchanged.',fg=MUTED)
            elif kind=='tray':
                if payload=='show':self.show()
                elif payload=='toggle':self.toggle_tunnel()
                elif payload=='apps':self.show();self.applications()
                elif payload=='networks':self.show();self.networks()
                elif payload=='links':self.show();self.link_controls()
                elif payload=='quit':self.quit()
            elif kind=='exit_checked':
                self.verifying=False
                checked_pid,result=payload
                if runtime and runtime['pid']==checked_pid:
                    self.exit_pid=checked_pid
                    self.exit_result.config(text=result,fg=CYAN if result.startswith('Verified') else AMBER)
        self.root.after(1000,self.tick)

    def toggle_tunnel(self):
        if self.testing or self.connect_pending:return
        active=live_status()
        self.connect_started=time.monotonic()
        self.connect_pending=True;self.connect.config(state='disabled',text='Disconnecting…' if active else 'Connecting…')
        self.notice.config(text='Stopping GameBond…' if active else 'Authenticating both links with your VPS…',fg=MUTED)
        def work():
            try:
                if active:
                    request_stop();self.events.put(('stopped',None))
                else:
                    path=ROOT/'.runtime/userspace.log';path.parent.mkdir(exist_ok=True)
                    with path.open('w') as output:
                        process=subprocess.Popen([sys.executable,'-m','gamebond.userspace'],cwd=ROOT,
                            stdout=output,stderr=subprocess.STDOUT,
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                    self.events.put(('started',process))
            except Exception as exc:
                self.connect_pending=False;self.events.put(('error',str(exc)))
        threading.Thread(target=work,daemon=True).start()

    def applications(self):
        from .capture import normalize_apps
        config=json.loads(CONFIG.read_text())
        window=tk.Toplevel(self.root);window.title('GameBond · Applications');window.configure(bg=BG)
        window.geometry('680x480');window.minsize(520,380);window.transient(self.root);window.grab_set()
        outer=tk.Frame(window,bg=BG);outer.pack(fill='both',expand=True,padx=22,pady=20)
        label(outer,'Route applications through your VPS',17,bold=True).pack(anchor='w',pady=(0,12))
        mode=tk.StringVar(value=config.get('capture_mode','all'))
        for value,text in (('all','All apps (default)'),('selected','Selected apps only')):
            tk.Radiobutton(outer,text=text,value=value,variable=mode,bg=BG,fg=TEXT,selectcolor=CARD,
                activebackground=BG,activeforeground=TEXT,font=('Segoe UI',11)).pack(anchor='w')
        label(outer,'Application list for Selected apps mode',10,MUTED).pack(anchor='w',pady=(16,6))
        area=tk.Frame(outer,bg=CARD);area.pack(fill='both',expand=True)
        scroll=tk.Scrollbar(area);scroll.pack(side='right',fill='y')
        horizontal=tk.Scrollbar(area,orient='horizontal');horizontal.pack(side='bottom',fill='x')
        listing=tk.Listbox(area,selectmode='extended',bg=CARD,fg=TEXT,selectbackground=BORDER,
            selectforeground=TEXT,font=('Segoe UI',10),borderwidth=0,highlightthickness=0,
            yscrollcommand=scroll.set,xscrollcommand=horizontal.set,exportselection=False)
        listing.pack(side='left',fill='both',expand=True);scroll.config(command=listing.yview)
        horizontal.config(command=listing.xview)
        for path in config.get('cod_executables',[]):listing.insert('end',path)
        actions=tk.Frame(outer,bg=BG);actions.pack(fill='x',pady=(8,0))
        def add():
            paths=filedialog.askopenfilenames(parent=window,title='Choose applications',filetypes=[('Applications','*.exe')])
            if not paths:return
            try:applications=normalize_apps(list(listing.get(0,'end'))+list(paths))
            except ValueError as exc:messagebox.showerror('Applications',str(exc),parent=window);return
            listing.delete(0,'end')
            for path in applications:listing.insert('end',path)
        def remove():
            for index in reversed(listing.curselection()):listing.delete(index)
        button(actions,'Add apps…',add).pack(side='left',padx=(0,8))
        button(actions,'Remove selected',remove).pack(side='left')
        label(outer,'IPv4 routing. GameBond’s carrier and helpers are excluded automatically.\nSave, then reconnect to apply. Existing connections may need reopening.',
              9,MUTED,wraplength=600,justify='left').pack(anchor='w',pady=(12,10))
        controls=tk.Frame(outer,bg=BG);controls.pack(fill='x')
        def save():
            try:self.config=save_applications(mode.get(),list(listing.get(0,'end')))
            except (ValueError,OSError,RuntimeError) as exc:
                messagebox.showerror('Could not save applications',str(exc),parent=window);return
            self.notice.config(text='Application routing saved. Reconnect to apply.' if live_status() else 'Application routing saved for the next connection.',fg=CYAN)
            window.destroy()
        button(controls,'Save settings',save,True).pack(side='right')
        button(controls,'Cancel',window.destroy).pack(side='left')

    def link_controls(self):
        from .link_policy import LinkPolicy, UsageLedger
        config=json.loads(CONFIG.read_text());runtime=live_status()
        links=self.monitor.snapshot()['links'];policies=dict(config.get('link_policies',{}))
        window=tk.Toplevel(self.root);window.title('GameBond · Link roles and limits');window.configure(bg=BG)
        window.geometry(f'640x{min(740,window.winfo_screenheight()-100)}');window.minsize(540,420)
        window.transient(self.root);window.grab_set()
        bottom=tk.Frame(window,bg=BG);bottom.pack(side='bottom',fill='x',padx=20,pady=16)
        canvas=tk.Canvas(window,bg=BG,highlightthickness=0)
        scroll=tk.Scrollbar(window,command=canvas.yview);scroll.pack(side='right',fill='y')
        canvas.pack(fill='both',expand=True);canvas.config(yscrollcommand=scroll.set)
        body=tk.Frame(canvas,bg=BG);item=canvas.create_window((0,0),window=body,anchor='nw')
        body.bind('<Configure>',lambda _:canvas.config(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda event:canvas.itemconfigure(item,width=event.width))
        label(body,'Link roles and limits',18,bold=True).pack(anchor='w',padx=20,pady=(20,6))
        label(body,'Primary: always use · Secondary: boost when needed\nBackup: only after other links fail · Never: disabled',
              10,MUTED,wraplength=580,justify='left').pack(anchor='w',padx=20,pady=(0,12))
        fields={}
        def option(parent,variable,values):
            widget=tk.OptionMenu(parent,variable,*values);widget.config(bg=BORDER,fg=TEXT,highlightthickness=0)
            widget['menu'].config(bg=CARD,fg=TEXT);return widget
        try:ledger=UsageLedger(ROOT/'.runtime/link-usage.json')
        except (ValueError,OSError):ledger=None
        for index in config['interface_indices']:
            key=str(index);policy=LinkPolicy(**policies.get(key,{}))
            link=next((row for row in links if row['index']==index),None)
            card=tk.Frame(body,bg=CARD);card.pack(fill='x',padx=20,pady=7)
            label(card,link['name'] if link else f'Adapter {index}',13,bold=True).pack(anchor='w',padx=14,pady=(12,4))
            usage=(runtime or {}).get('link_usage',{}).get(key)
            if usage is None and ledger:usage=ledger.usage(key,policy)
            if usage:label(card,f"Today {human_bytes(usage['daily_bytes'])} · Billing cycle {human_bytes(usage['monthly_bytes'])}",9,MUTED).pack(anchor='w',padx=14)
            grid=tk.Frame(card,bg=CARD);grid.pack(fill='x',padx=14,pady=10)
            grid.columnconfigure(1,weight=1);grid.columnconfigure(3,weight=1)
            variables={}
            for row,(name,title,value) in enumerate((
                ('role','Role',policy.role),('upload_mbps','Upload limit (Mbps)',policy.upload_mbps),
                ('download_mbps','Download limit (Mbps)',policy.download_mbps),('daily_bytes','Daily cap (GB)',policy.daily_bytes/1e9),
                ('monthly_bytes','Monthly cap (GB)',policy.monthly_bytes/1e9),('reset_day','Billing reset day',policy.reset_day),
                ('overlimit','At data cap',policy.overlimit),('overlimit_mbps','Overlimit rate (Mbps)',policy.overlimit_mbps))):
                variable=tk.StringVar(value=str(value));variables[name]=variable
                column=(row%2)*2;line=row//2
                label(grid,title,9,MUTED).grid(row=line*2,column=column,columnspan=2,sticky='w',pady=(6,2))
                if name in ('role','overlimit'):
                    editor=option(grid,variable,('primary','secondary','backup','never') if name=='role' else ('stop','throttle'))
                else:editor=tk.Entry(grid,textvariable=variable,bg=BG,fg=TEXT,insertbackground=TEXT,relief='flat',width=16)
                editor.grid(row=line*2+1,column=column,columnspan=2,sticky='ew',padx=(0,12) if column==0 else 0)
            fields[key]=variables
        label(body,'0 means no configured limit. GB uses 1,000,000,000 bytes.\nUsage includes duplicate and repair traffic. Allow headroom for in-flight traffic at a cap.',
              9,MUTED,wraplength=580,justify='left').pack(anchor='w',padx=20,pady=12)
        feedback=label(bottom,'Save and reconnect to apply these settings.',9,MUTED,wraplength=580,justify='left')
        feedback.pack(anchor='w',pady=(0,8))
        controls=tk.Frame(bottom,bg=BG);controls.pack(fill='x')
        def save():
            try:
                for key,variables in fields.items():
                    values={name:value.get().strip() for name,value in variables.items()}
                    for name in ('upload_mbps','download_mbps','overlimit_mbps'):values[name]=float(values[name])
                    for name in ('daily_bytes','monthly_bytes'):values[name]=int(float(values[name])*1e9)
                    values['reset_day']=int(values['reset_day']);policies[key]=LinkPolicy(**values).to_dict()
                self.config=save_link_policies(policies)
            except (ValueError,TypeError,OSError,RuntimeError,OverflowError) as exc:
                feedback.config(text=str(exc),fg=AMBER);return
            self.notice.config(text='Link roles and limits saved. Reconnect to apply.',fg=CYAN);window.destroy()
        button(controls,'Save settings',save,True).pack(side='right')
        button(controls,'Cancel',window.destroy).pack(side='left')

    def _ensure_linkcards(self):
        count=min(MAX_LINKS,len(self.config.get('interface_indices',[])))
        if count==len(self.linkcards):return
        while len(self.linkcards)>count:self.linkcards.pop().destroy()
        while len(self.linkcards)<count:self.linkcards.append(LinkCard(self.linkcards_frame))
        columns=min(4,max(1,count))
        for column in range(4):self.linkcards_frame.columnconfigure(column,weight=1 if column<columns else 0,uniform='link')
        for index,card in enumerate(self.linkcards):card.grid(row=index//columns,column=index%columns,sticky='nsew',padx=5,pady=4)

    def networks(self):
        window=tk.Toplevel(self.root);window.title('GameBond · Select networks');window.configure(bg=BG)
        window.geometry('510x430');window.resizable(False,False);window.transient(self.root)
        window.grab_set()
        label(window,'Select your networks',18,bold=True).pack(anchor='w',padx=24,pady=(22,4))
        label(window,'Choose 1 to 8 links. One link runs the VPN; more links enable bonding.',10,MUTED).pack(anchor='w',padx=24)
        options=tk.Frame(window,bg=BG);options.pack(fill='both',expand=True,padx=24,pady=15)
        links=self.monitor.snapshot()['links'];variables=[]
        for link in links:
            value=tk.BooleanVar(value=link['index'] in self.config.get('interface_indices',[]))
            usable=link['up'] and link['addresses'] and link['gateway']
            text=f"{link['name']}   ·   "+(link['addresses'][0] if link['addresses'] else 'No IPv4 address')
            tk.Checkbutton(options,text=text,variable=value,bg=CARD,fg=TEXT,selectcolor=BORDER,
                           activebackground=CARD,activeforeground=TEXT,font=('Segoe UI',11),
                           anchor='w',padx=12,pady=12,state='normal' if usable else 'disabled').pack(fill='x',pady=4)
            variables.append((link['index'],value))
        feedback=label(window,'This changes GameBond configuration, not Windows adapters.',9,MUTED,wraplength=460,justify='left')
        feedback.pack(fill='x',padx=24,pady=(0,8))
        controls=tk.Frame(window,bg=BG);controls.pack(fill='x',padx=24,pady=(0,22))
        def save():
            selected=[index for index,value in variables if value.get()]
            # Preserve the existing path order when the same links are selected.
            if set(selected)==set(self.config.get('interface_indices',[])):selected=self.config['interface_indices']
            if not MIN_LINKS<=len(selected)<=MAX_LINKS:
                feedback.config(text='Choose 1 to 8 different networks.',fg=AMBER);return
            apply.config(state='disabled',text='Saving…')
            def work():
                try:self.events.put(('selection',save_selection(selected)))
                except Exception as exc:self.events.put(('error',str(exc)))
            threading.Thread(target=work,daemon=True).start();window.destroy()
        apply=button(controls,'Save selection',save,True);apply.pack(side='right')
        button(controls,'Cancel',window.destroy).pack(side='left')

    def test(self):
        if self.testing or live_status() or self.connect_pending:return
        self.testing=True;self.check.config(state='disabled',text='Checking your VPS…')
        self.notice.config(text='Testing TCP, UDP and path failover through your VPS…',fg=MUTED)
        def work():
            try:
                log=ROOT/'.runtime/widget-connection-check.log';log.parent.mkdir(exist_ok=True)
                with log.open('w') as output:
                    result=subprocess.run([sys.executable,str(ROOT/'tools/test_netstack_e2e.py'),'--wan-direct'],
                        cwd=ROOT,stdout=output,stderr=subprocess.STDOUT,timeout=100,
                        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                if result.returncode:raise RuntimeError('VPS check failed. Details: .runtime/widget-connection-check.log')
                report=json.loads((ROOT/'evidence/netstack-wan-e2e.json').read_text())
                self.events.put(('tested',report))
            except Exception as exc:self.events.put(('error',str(exc)))
        threading.Thread(target=work,daemon=True).start()

    def show(self):
        self.root.deiconify();self.root.lift()

    def verify_exit(self):
        runtime=live_status()
        if self.verifying or not runtime or runtime['state']!='running':return
        self.verifying=True;self.exit_result.config(text='Verifying TCP and UDP exit addresses…',fg=MUTED)
        def work():
            try:
                result=subprocess.run([str(ROOT/'build/gamebond-internet-probe.exe'),'--internet-probe'],
                    capture_output=True,text=True,timeout=25,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                if result.returncode:raise RuntimeError(result.stderr.strip() or 'Exit probe failed')
                report=json.loads(result.stdout)
                expected=runtime['peer'][0]
                if report.get('egress_ipv4')!=expected or report.get('udp_egress_ipv4')!=expected:
                    raise RuntimeError('TCP or UDP is bypassing your configured VPS')
                result=f'Verified TCP + UDP exit: {expected}'
            except Exception as exc:result='Exit verification failed: '+str(exc)
            self.events.put(('exit_checked',(runtime['pid'],result)))
        threading.Thread(target=work,daemon=True).start()

    def quit(self):
        if self.testing:
            self.show()
            messagebox.showinfo('Connection check running','Wait for the VPS check to finish before quitting.',parent=self.root)
            return
        if self.connect_pending:
            self.show();self.notice.config(text='Wait for the current connection action to finish before quitting.',fg=AMBER);return
        if live_status():
            self.quitting=True;self.toggle_tunnel();return
        self.finish_quit()

    def finish_quit(self):
        if self.tray:self.tray.close()
        self.closed=True;self.monitor.stop.set();self.root.destroy()

    def close(self):
        if self.tray and self.tray.visible:
            self.root.withdraw()
        else:self.quit()


def main():
    if os.name=='nt':
        try:ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except OSError:pass
    lease=None
    if os.name=='nt':
        from .tray import AgentLease
        lease=AgentLease(ROOT)
        if not lease.owner:lease.close();return
    try:
        root=tk.Tk();widget=Widget(root,lease);root.mainloop()
    finally:
        if 'widget' in locals() and widget.tray:widget.tray.close()
        if lease:lease.close()

if __name__=='__main__':main()
