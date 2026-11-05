"""Native Qt dashboard, tray agent and bounded GameBond lifecycle controller."""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import time

import psutil
from PyQt5.QtCore import QObject,QPoint,Qt,QTimer,pyqtSignal,pyqtSlot,QSize
from PyQt5.QtGui import QColor,QFont,QIcon,QPainter,QPen,QPixmap,QCursor
from PyQt5.QtWidgets import (QAbstractButton,QApplication,QFrame,QHBoxLayout,QLabel,QMainWindow,
    QMenu,QPushButton,QGridLayout,QSizeGrip,QStackedWidget,QSystemTrayIcon,QToolButton,QVBoxLayout,QWidget,QSizePolicy)

from .glass_theme import GlassTheme,ROOT,load_fonts
from .glass_panels import HardwarePanel,NetworkScannerPanel,_AsyncCall
from .tray import AgentLease
from .userspace import live_status,request_stop,STATUS
from .widget_data import CONFIG,Monitor
from .atomic_io import read_json_shared
from .link_limits import MAX_LINKS

HIDDEN=getattr(subprocess,'CREATE_NO_WINDOW',0)


def _read_json(path,limit=4*1024*1024):
    path=Path(path)
    if path.stat().st_size>limit:raise ValueError('Status file exceeds its size limit')
    return read_json_shared(path,limit)


def _process_matches(record):
    try:
        process=psutil.Process(record['pid'])
        return abs(process.create_time()-record['created'])<.01 and process.is_running()
    except (psutil.Error,KeyError,TypeError):return False


class NewAppCursor:
    """Only fresh native-attributed success events may trigger a toast."""
    def __init__(self,history_path=None,*,latest=None):
        if latest is None:
            try:latest=_read_json(history_path or ROOT/'.runtime/app-history.json').get('sequence',0)
            except (OSError,ValueError,TypeError):latest=None
        self.latest=latest if type(latest) is int and latest>=0 else None
        self.pid=None

    def observe(self,runtime):
        if not runtime:return []
        batch=runtime.get('app_events') or {};latest=batch.get('latest_id')
        if type(latest) is not int or latest<0:return []
        if self.latest is None or (self.pid is not None and runtime.get('pid')!=self.pid and latest<self.latest):
            self.latest=latest;self.pid=runtime.get('pid');return []
        self.pid=runtime.get('pid');after=self.latest;self.latest=max(self.latest,latest)
        attribution=runtime.get('app_attribution') or {}
        if not attribution.get('available') or attribution.get('source')!='native_capture_owner_and_tunnel_success' or attribution.get('history_error'):
            return []
        result=[]
        for event in batch.get('events',[])[:256]:
            if not isinstance(event,dict) or type(event.get('id')) is not int or not after<event['id']<=latest:continue
            app=event.get('application');stamp=event.get('timestamp')
            if (event.get('kind')!='new_app_tunnel_use' or event.get('attribution')!='native_capture_owner_and_tunnel_success'
                    or event.get('proof') not in ('tcp_connect','udp_reply') or event.get('protocol') not in ('tcp','udp')
                    or (event['proof']=='tcp_connect')!=(event['protocol']=='tcp') or not isinstance(app,dict)
                    or not isinstance(app.get('path'),str) or not ntpath.isabs(app['path']) or '\0' in app['path']
                    or type(app.get('pid')) is not int or app['pid']<=0
                    or not isinstance(app.get('created_filetime'),str) or not app['created_filetime'].isdecimal()
                    or len(app['created_filetime'])>20 or int(app['created_filetime'])<=116444736000000000
                    or type(stamp) not in (int,float) or not math.isfinite(stamp) or stamp<0):
                continue
            result.append(dict(event))
        return sorted(result,key=lambda event:event['id'])


class BackendController(QObject):
    stateChanged=pyqtSignal(object,object)
    error=pyqtSignal(str)
    busyChanged=pyqtSignal(bool)
    stopped=pyqtSignal()

    def __init__(self,parent=None,*,monitor=None,autostart=True):
        super().__init__(parent)
        self.monitor=monitor or Monitor();self.runtime=None;self.snapshot={};self.initialized=False
        self.process=None;self.command=None;self.deadline=None;self.target=None;self.closed=False;self.force_sent=False
        self.poll_worker=_AsyncCall(self);self.poll_worker.done.connect(self._polled);self.poll_worker.failed.connect(self._poll_failed)
        self.operation_worker=_AsyncCall(self);self.operation_worker.done.connect(self._operation_done);self.operation_worker.failed.connect(self._operation_failed)
        self.timer=QTimer(self);self.timer.setInterval(750);self.timer.timeout.connect(self.poll)
        if autostart:self.timer.start();QTimer.singleShot(0,self.poll)

    @property
    def busy(self):return self.command is not None or self.operation_worker.busy

    @pyqtSlot()
    def poll(self):
        if self.closed or self.poll_worker.busy:return
        def read():
            runtime=live_status();data=self.monitor.snapshot();raw=None;start_error=None
            if runtime is None:
                try:raw=_read_json(STATUS,1024*1024)
                except (OSError,ValueError):pass
            process=self.process
            exit_code=process.poll() if process else None
            if process and exit_code not in (None,0):
                try:
                    record=_read_json(ROOT/'.runtime/userspace-start-error.json',65536)
                    if record.get('pid')==process.pid:start_error=record.get('error')
                except (OSError,ValueError):pass
            return dict(runtime=runtime,data=data,raw=raw,raw_alive=bool(raw and _process_matches(raw)),exit_code=exit_code,
                        process_pid=process.pid if process else None,start_error=start_error)
        self.poll_worker.start(read)

    @pyqtSlot(object)
    def _polled(self,result):
        if self.closed:return
        runtime,data=result['runtime'],result['data'];previous=self.runtime
        self.runtime=runtime;self.snapshot=data;self.initialized=True
        data=dict(data)
        if runtime is None and result.get('raw_alive'):
            data['agent_problem']='Tunnel process is alive but its status is stale'
        elif runtime is None and (result.get('raw') or {}).get('state')=='failed':
            data['agent_problem']=result['raw'].get('error') or 'Tunnel failed'
        if self.command=='start':
            if runtime and runtime.get('waiting_for_network'):self.deadline=time.monotonic()+35
            if runtime and runtime.get('state')=='running':self._settled()
            elif self.process and result['exit_code'] is not None:
                self._operation_failed(result.get('start_error') or 'Tunnel stopped before becoming ready; inspect .runtime/userspace.log')
        elif self.command in ('stop','force_stop'):
            owned_alive=self.process is not None and result['exit_code'] is None
            if runtime is None and not result.get('raw_alive') and not owned_alive and not self.operation_worker.busy:
                self._settled();self.stopped.emit()
        if self.deadline and time.monotonic()>self.deadline:
            if self.command=='start':
                self._operation_failed('Tunnel startup timed out; stopping the incomplete startup')
                self.stop()
            elif self.command=='stop' and not self.force_sent:
                self._force_stop()
            elif self.command=='force_stop':self._operation_failed('Could not stop the tunnel process; the interface remains open')
        if previous and previous['pid']==result.get('process_pid') and runtime is None and result.get('exit_code') not in (None,0):
            data['agent_problem']=result.get('start_error') or 'Tunnel process exited unexpectedly'
        if result.get('exit_code') is not None and self.command!='start':self.process=None
        self.stateChanged.emit(runtime,data)

    @pyqtSlot(str)
    def _poll_failed(self,message):
        if not self.closed:self.error.emit('Could not read connection status: '+message)

    def _settled(self):
        self.command=None;self.deadline=None;self.force_sent=False;self.busyChanged.emit(False)

    @pyqtSlot()
    def toggle(self):
        if self.command=='start' and not self.operation_worker.busy:
            self.stop();return
        if self.busy or not self.initialized:return
        if self.runtime:self.stop()
        else:self.start()

    @pyqtSlot()
    def start(self):
        if self.busy or self.closed:return
        self.command='start';self.deadline=time.monotonic()+35;self.busyChanged.emit(True)
        def work():
            current=live_status()
            if current:return dict(action='attached',runtime=current)
            path=ROOT/'.runtime/userspace.log';path.parent.mkdir(exist_ok=True)
            with path.open('w',encoding='utf-8') as output:
                process=subprocess.Popen([sys.executable,'-m','gamebond.userspace'],cwd=ROOT,
                    stdout=output,stderr=subprocess.STDOUT,creationflags=HIDDEN)
            return dict(action='started',process=process)
        self.operation_worker.start(work)

    @pyqtSlot()
    def stop(self):
        if self.operation_worker.busy or self.closed:return False
        self.command='stop';self.deadline=time.monotonic()+15;self.force_sent=False;self.busyChanged.emit(True)
        def work():
            current=live_status()
            if current:request_stop()
            else:
                try:
                    raw=_read_json(STATUS,1024*1024)
                    current=raw if _process_matches(raw) else None
                except (OSError,ValueError):current=None
            return dict(action='stop_requested',target=current)
        self.operation_worker.start(work);return True

    def _force_stop(self):
        if self.operation_worker.busy:return
        target=self.target
        if target is None and self.process:
            try:target=dict(pid=self.process.pid,created=psutil.Process(self.process.pid).create_time())
            except psutil.Error:pass
        self.force_sent=True;self.command='force_stop';self.deadline=time.monotonic()+5
        def work():
            if target and _process_matches(target):
                process=psutil.Process(target['pid']);command=process.cmdline()
                if not any(command[i:i+2]==['-m','gamebond.userspace'] for i in range(len(command)-1)):
                    raise RuntimeError('Refusing to stop a process that is not the GameBond runtime')
                process.terminate();process.wait(timeout=3)
            return dict(action='force_stopped')
        self.operation_worker.start(work)

    @pyqtSlot(object)
    def _operation_done(self,result):
        if self.closed:return
        if result['action']=='started':self.process=result['process']
        elif result['action']=='attached':self.runtime=result['runtime'];self._settled()
        elif result['action']=='stop_requested':self.target=result.get('target')
        self.poll()

    @pyqtSlot(str)
    def _operation_failed(self,message):
        if self.closed:return
        self._settled();self.error.emit(message)

    def shutdown(self):
        self.closed=True;self.timer.stop();self.poll_worker.shutdown();self.operation_worker.shutdown();self.monitor.stop.set()


def _tray_icon(color):
    pixmap=QPixmap(64,64);pixmap.fill(Qt.transparent)
    painter=QPainter(pixmap);painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen);painter.setBrush(QColor(color));painter.drawRoundedRect(2,2,60,60,14,14)
    painter.setPen(QPen(QColor('#ffffff'),6,Qt.SolidLine,Qt.RoundCap,Qt.RoundJoin))
    from PyQt5.QtGui import QPolygon
    painter.drawPolyline(QPolygon([QPoint(12,47),QPoint(27,17),QPoint(38,36),QPoint(53,11)]));painter.end()
    return QIcon(pixmap)


class _TitleBar(QFrame):
    def __init__(self,window):super().__init__(window);self.window=window;self.drag=None
    def mousePressEvent(self,event):
        if event.button()==Qt.LeftButton:self.drag=event.globalPos()-self.window.frameGeometry().topLeft();event.accept()
    def mouseMoveEvent(self,event):
        if self.drag is not None and event.buttons()&Qt.LeftButton and not self.window.isMaximized():
            self.window.move(event.globalPos()-self.drag);event.accept()
    def mouseReleaseEvent(self,event):self.drag=None
    def mouseDoubleClickEvent(self,event):
        if event.button()==Qt.LeftButton:self.window.toggle_maximized()


class GlassDashboard(QMainWindow):
    settingsChanged=pyqtSignal(dict)

    def __init__(self,parent=None,*,theme=None,controller=None,lease=None,panel_factories=None,
                 toast_factory=None,tray_enabled=True):
        super().__init__(parent)
        self.theme=theme or GlassTheme();self.lease=lease
        self.setWindowFlags(Qt.Window|Qt.FramelessWindowHint)
        self.setWindowTitle('GameBond');self.resize(1120,760);self.setMinimumSize(860,560)
        self.setStyleSheet(self.theme.stylesheet())
        self.config=_read_json(CONFIG);self.runtime=None;self.monitor_data={};self.problem=None
        self.pending_settings=False;self._runtime_pid=None;self._final_close=False;self._quitting=False
        self.reload_requested=False;self.flash=False;self.dialogs=[]
        self.controller=controller or BackendController(self)
        self.cursor=NewAppCursor()
        self.icons={name:_tray_icon(color) for name,color in (('connected','#00c853'),('disconnected','#000000'),('problem','#f2be70'))}
        self.setWindowIcon(self.icons['connected'])
        self._build(panel_factories)
        if toast_factory is None:
            from .glass_toasts import ToastManager
            toast_factory=ToastManager
        self.toasts=toast_factory(self._toast_activated,self.theme)
        self._build_tray(tray_enabled)
        self.controller.stateChanged.connect(self._state_changed);self.controller.error.connect(self._error)
        self.controller.busyChanged.connect(self._busy_changed);self.controller.stopped.connect(self._tunnel_stopped)
        self.tray_timer=QTimer(self);self.tray_timer.setInterval(500);self.tray_timer.timeout.connect(self._tray_tick);self.tray_timer.start()

    def _build(self,panel_factories):
        body=QWidget();body.setObjectName('glassMainBody');self.setCentralWidget(body)
        outer=QVBoxLayout(body);outer.setContentsMargins(1,1,1,1);outer.setSpacing(0)
        self.topbar=_TitleBar(self);self.topbar.setObjectName('glassTopBar');self.topbar.setFixedHeight(84)
        top=QHBoxLayout(self.topbar);top.setContentsMargins(8,8,8,8);top.setSpacing(8)
        brand=QLabel('GAMEBOND');brand.setObjectName('glassBrand');brand.setAttribute(Qt.WA_TransparentForMouseEvents)
        brand.setFont(QFont('Oswald',18,QFont.Medium));brand.setMinimumWidth(118)
        brand.setAlignment(Qt.AlignLeft|Qt.AlignTop);brand.setContentsMargins(0,4,0,0);top.addWidget(brand,0,Qt.AlignTop)
        nav=QWidget();nav.setObjectName('glassNavigation');nav_layout=QHBoxLayout(nav);nav_layout.setContentsMargins(4,0,4,0);nav_layout.setSpacing(4)
        self.nav=[]
        definitions=(('Traffic\nMonitor','graph'),('Protect','firewall'),('Log\nAnalysis','alerts'),('Network\nScanner','things'),('Hardware\nResources','hardware'),('DNS','things'))
        for index,(text,icon) in enumerate(definitions):
            button=QToolButton();button.setObjectName('glassNavButton');button.setText(text);button.setCheckable(True);button.setAutoExclusive(True)
            button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon);button.setIconSize(QSize(20,20));button.setFixedHeight(42)
            button.setMinimumWidth(72);button.setSizePolicy(button.sizePolicy().Expanding,button.sizePolicy().Preferred)
            button.clicked.connect(lambda checked=False,index=index:self.select_tab(index));button.setProperty('asset',icon)
            self.nav.append(button);nav_layout.addWidget(button,1)
        top.addWidget(nav,1)
        self.connect_button=QPushButton('Checking…');self.connect_button.setObjectName('glassConnectButton');self.connect_button.setFixedSize(112,32)
        self.connect_button.setEnabled(False);self.connect_button.clicked.connect(self.controller.toggle);top.addWidget(self.connect_button)
        controls=QWidget();buttons=QHBoxLayout(controls);buttons.setContentsMargins(0,0,0,0);buttons.setSpacing(0)
        for text,asset,handler in (('Minimize','window-minimize-button.svg',self.showMinimized),
                ('Maximize / Restore','window-expand-button.svg',self.toggle_maximized),('Hide to tray','window-close-button.svg',self.close)):
            button=QToolButton();button.setObjectName('glassCloseButton' if asset.startswith('window-close') else 'glassWindowButton')
            button.setToolTip(text);button.setFixedSize(25,28);button.setIconSize(QSize(12,12));button.setIcon(self.theme.icon('MainTopPanel/'+asset,size=12))
            button.clicked.connect(handler);buttons.addWidget(button)
            if asset.startswith('window-expand'):self.maximize_button=button
        top.addWidget(controls,0,Qt.AlignTop);outer.addWidget(self.topbar)
        networks=QFrame();networks.setObjectName('glassNetworksStrip')
        network_row=QHBoxLayout(networks);network_row.setContentsMargins(14,7,14,7);network_row.setSpacing(14)
        network_cards=QWidget();self.network_grid=QGridLayout(network_cards)
        self.network_grid.setContentsMargins(0,0,0,0);self.network_grid.setSpacing(10)
        self.network_labels=[];self.network_cards=[]
        network_row.addWidget(network_cards,1)
        self._rebuild_network_cards()
        self.network_button=QPushButton('Select networks');self.network_button.setObjectName('glassSelectNetworksButton');self.network_button.clicked.connect(self.open_networks)
        self.link_limits_button=QPushButton('Link roles & limits');self.link_limits_button.setObjectName('glassLinkLimitsButton');self.link_limits_button.clicked.connect(self.open_link_controls)
        network_row.addWidget(self.network_button);network_row.addWidget(self.link_limits_button);outer.addWidget(networks)
        self.views=QStackedWidget();self.views.setObjectName('glassPanelStack');outer.addWidget(self.views,1)
        if panel_factories is None:
            from .glass_traffic import TrafficPanel
            from .glass_logs import LogPanel
            from .glass_protect import ProtectPanel
            from .glass_dns import DNSPanel
            panel_factories=[lambda:TrafficPanel(theme=self.theme),lambda:ProtectPanel(theme=self.theme),lambda:LogPanel(theme=self.theme),
                             lambda:NetworkScannerPanel(theme=self.theme.values),lambda:HardwarePanel(theme=self.theme.values),DNSPanel]
        elif len(panel_factories)==5:
            from .glass_dns import DNSPanel
            panel_factories=list(panel_factories)+[DNSPanel]
        self.panels=[factory() for factory in panel_factories]
        for panel in self.panels:self.views.addWidget(panel)
        self.traffic,self.protect,self.logs,self.scanner,self.hardware=self.panels[:5];self.dns=self.panels[5]
        if hasattr(self.protect,'settingsChanged'):self.protect.settingsChanged.connect(self._settings_saved)
        if hasattr(self.dns,'settingsChanged'):self.dns.settingsChanged.connect(self._settings_saved)
        if hasattr(self.scanner,'set_icon_provider'):
            self.scanner.set_icon_provider(lambda device:self.theme.icon('DeviceIcons/icUnknown.svg',size=24))
        footer=QFrame();footer.setObjectName('glassSessionStrip');footer.setFixedHeight(30)
        row=QHBoxLayout(footer);row.setContentsMargins(12,0,4,0);row.setSpacing(8)
        self.status_icon=QLabel();self.status_icon.setFixedSize(14,14);row.addWidget(self.status_icon)
        self.status=QLabel('Checking connection status…');self.status.setObjectName('glassSessionStatus');row.addWidget(self.status,1)
        settings=QToolButton();settings.setText('Settings');settings.setObjectName('glassSettingsButton');settings.setPopupMode(QToolButton.InstantPopup)
        menu=self._settings_menu();settings.setMenu(menu);row.addWidget(settings);row.addWidget(QSizeGrip(self));outer.addWidget(footer)
        self.setStyleSheet(self.theme.stylesheet()+f'''
            QWidget#glassMainBody {{border:1px solid #d9dde2;background:{self.theme.css('gw_mainbg')};}}
            QFrame#glassTopBar {{background:{self.theme.css('topnav_bgd')};border-bottom:1px solid {self.theme.css('topnav_bottomline1')};}}
            QToolButton#glassNavButton {{border:0;border-radius:12px;background:transparent;padding:4px 7px;font-size:11px;}}
            QToolButton#glassNavButton:checked {{background:rgba(93,128,240,28);color:#3d6fea;}}
            QToolButton#glassNavButton:hover {{background:rgba(93,128,240,16);}}
            QToolButton#glassWindowButton,QToolButton#glassCloseButton {{background:transparent;border:0;border-radius:0;padding:0;}}
            QToolButton#glassWindowButton:hover {{background:#e9edf2;}}
            QToolButton#glassCloseButton:hover {{background:#ff6060;}}
            QFrame#glassSessionStrip {{background:{self.theme.css('gw_mainbg')};border-top:1px solid {self.theme.css('graph_bottomline')};}}
            QLabel#glassSessionStatus {{font-size:10px;color:#9299a2;}}
            QToolButton#glassSettingsButton {{border:0;background:transparent;padding:3px 8px;font-size:10px;}}
        ''')
        self.select_tab(0)

    def _settings_menu(self):
        menu=QMenu(self)
        menu.addAction('Application routing',self.open_applications)
        menu.addAction('Select networks',self.open_networks)
        menu.addAction('Link roles and limits',self.open_link_controls)
        menu.addAction('DNS settings',lambda:self.select_tab(5))
        menu.addSeparator();menu.addAction('Reload interface (keep tunnel)',self.reload_interface)
        return menu

    def _build_tray(self,enabled):
        self.tray=QSystemTrayIcon(self.icons['disconnected'],self)
        menu=QMenu(self);menu.addAction('Show GameBond',self.show_dashboard)
        self.tray_connect=menu.addAction('Connect',self.controller.toggle)
        menu.addSeparator();menu.addAction('Application routing',self.open_applications)
        menu.addAction('Select networks',self.open_networks);menu.addAction('Link roles and limits',self.open_link_controls)
        menu.addSeparator();menu.addAction('Reload interface (keep tunnel)',self.reload_interface)
        self.tray_quit=menu.addAction('Quit (stop tunnel)',self.quit)
        self.tray.setContextMenu(menu);self.tray.setToolTip('GameBond · Checking status')
        self.tray.activated.connect(self._tray_activated)
        self.tray_available=bool(enabled and QSystemTrayIcon.isSystemTrayAvailable())
        if self.tray_available:self.tray.show()

    def _update_panel_activity(self):
        visible=self.isVisible() and not self.isMinimized()
        for index,panel in enumerate(self.panels):
            if hasattr(panel,'set_active'):panel.set_active(visible and index==self.views.currentIndex())

    def showEvent(self,event):
        super().showEvent(event)
        if hasattr(self,'panels'):self._update_panel_activity()

    def hideEvent(self,event):
        super().hideEvent(event)
        if hasattr(self,'panels'):self._update_panel_activity()

    def changeEvent(self,event):
        super().changeEvent(event)
        if hasattr(self,'panels'):self._update_panel_activity()

    def select_tab(self,index):
        self.views.setCurrentIndex(index);self._update_panel_activity()
        for i,button in enumerate(self.nav):
            button.setChecked(i==index);button.setIcon(self.theme.icon('MainTopPanel/ico-top-'+button.property('asset')+'.svg','c' if i==index else 'n'))

    def resizeEvent(self,event):
        super().resizeEvent(event)
        for button in getattr(self,'nav',[]):button.setToolButtonStyle(Qt.ToolButtonTextOnly if self.width()<1000 else Qt.ToolButtonTextBesideIcon)

    @pyqtSlot(object,object)
    def _state_changed(self,runtime,data):
        if self._final_close:return
        self.runtime=runtime;self.monitor_data=data
        if runtime:
            if self._runtime_pid is not None and runtime['pid']!=self._runtime_pid:self.pending_settings=False
            self._runtime_pid=runtime['pid'];self.problem=None
        if data.get('agent_problem'):self.problem=data['agent_problem']
        for panel in (self.traffic,self.protect,self.logs,self.dns):
            if hasattr(panel,'update_runtime'):panel.update_runtime(runtime)
        for event in self.cursor.observe(runtime):self.toasts.push(event)
        self._update_networks()
        self._update_status()
        if self._quitting and not runtime and not self.controller.busy:self._finish_close()

    def _update_status(self):
        runtime=self.runtime;busy=self.controller.busy
        state=runtime.get('state') if runtime else None
        connected=state=='running'
        command=getattr(self.controller,'command',None)
        cancellable=(command=='start' or state in ('starting','connecting')) and not self.controller.operation_worker.busy if hasattr(self.controller,'operation_worker') else False
        label='Stopping…' if command in ('stop','force_stop') or state=='stopping' else 'Disconnect' if connected else 'Cancel connection' if cancellable else 'Connecting…' if busy or state in ('starting','connecting') else 'Connect'
        self.connect_button.setText(label);self.tray_connect.setText('Disconnect' if runtime else 'Connect')
        enabled=self.controller.initialized and not busy and state not in ('starting','connecting','stopping')
        if cancellable:enabled=True
        self.connect_button.setEnabled(enabled);self.tray_connect.setEnabled(enabled)
        if runtime:
            paths=[p for p in runtime.get('transport',{}).get('paths',[]) if p.get('enabled',True)]
            healthy=sum(bool(p.get('healthy')) for p in paths)
            scope='All apps' if runtime.get('capture_mode')=='all' else 'Selected apps'
            connection=('Connected' if healthy and healthy==len(paths) else 'Degraded connection' if healthy else 'Reconnecting') if state=='running' else state.capitalize()
            text=f"{connection} · VPS {runtime['peer'][0]} · {healthy}/{len(paths)} enabled links · {scope} · IPv4"
            missing=runtime.get('unavailable_links',[])
            if missing:text+=' · Waiting for '+', '.join(row['name'] for row in missing)
            if runtime.get('waiting_for_network'):text='Waiting for a selected network · '+text
        else:text='Disconnected · traffic is direct' if self.controller.initialized else 'Checking connection status…'
        if self.problem:text='Network problem · '+self.problem
        elif self.pending_settings:text+=' · Settings saved; reconnect to apply'
        self.status.setText(text);self.status.setToolTip(text)
        if getattr(self,'_button_connected',None)!=connected:
            self._button_connected=connected
            self.connect_button.setStyleSheet('background:#6ad68c;color:white;border:0;border-radius:16px;' if connected else '')
        self._tray_tick()

    def _rebuild_network_cards(self):
        count=min(MAX_LINKS,len(self.config.get('interface_indices',[])))
        if count==len(self.network_labels):return
        for card in self.network_cards:self.network_grid.removeWidget(card);card.deleteLater()
        self.network_labels=[];self.network_cards=[]
        columns=min(4,max(1,count))
        for slot in range(count):
            card=QWidget();card.setMinimumWidth(0);column=QVBoxLayout(card)
            column.setContentsMargins(0,0,0,0);column.setSpacing(1)
            labels=[QLabel() for _ in range(3)]
            for label in labels:label.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Preferred);column.addWidget(label)
            labels[0].setStyleSheet('font-weight:600;');labels[2].setStyleSheet('font-size:10px;color:#7b8490;')
            self.network_labels.append(labels);self.network_cards.append(card)
            self.network_grid.addWidget(card,slot//columns,slot%columns)
        for column in range(4):self.network_grid.setColumnStretch(column,1 if column<columns else 0)

    def _update_networks(self):
        self._rebuild_network_cards()
        links=self.monitor_data.get('links',[]);indices=self.config.get('interface_indices',[]);ids=self.config.get('interface_ids',[])
        paths=(self.runtime or {}).get('transport',{}).get('paths',[])
        for slot,labels in enumerate(self.network_labels):
            index=indices[slot] if slot<len(indices) else None;identity=ids[slot].casefold() if slot<len(ids) else ''
            row=next((r for r in links if (str(r.get('id','')).casefold()==identity if identity else r['index']==index)),None)
            names=self.config.get('interface_names',[]);name=(row or {}).get('name') or (names[slot] if slot<len(names) else f'Adapter {index}')
            address=((row or {}).get('addresses') or ['No IPv4'])[0]
            available=bool(row and row.get('up') and row.get('addresses') and row.get('gateway'))
            path=next((p for p in paths if p.get('interface_index')==((row or {}).get('index',index)) or ('interface_index' not in p and p.get('slot')==slot)),None)
            state='Connected' if path and path.get('healthy') else 'Connecting' if available and self.runtime else 'Available' if available else 'Offline'
            if path and not path.get('enabled',True):state='Disabled'
            rate=self.monitor_data.get('rates',{}).get(name,{}) if available else {}
            labels[0].setText(name);labels[1].setText(f'{state} · {address}')
            labels[1].setStyleSheet('color:#00a66c;' if state=='Connected' else 'color:#b38126;' if state in ('Offline','Connecting') else 'color:#7b8490;')
            labels[2].setText(f"Adapter ↓ {rate.get('down',0)*8/1e6:.2f}  ↑ {rate.get('up',0)*8/1e6:.2f} Mbps")
            for label in labels:label.setToolTip(f"{name}\n{state} · {address}\nAdapter traffic includes traffic outside the tunnel.")
    @pyqtSlot()
    def _tray_tick(self):
        if self.lease and self.lease.show_requested():self.show_dashboard()
        runtime=self.runtime;paths=[p for p in (runtime or {}).get('transport',{}).get('paths',[]) if p.get('enabled',True)]
        healthy=sum(bool(p.get('healthy')) for p in paths)
        state=(runtime or {}).get('state')
        issue=bool(self.problem) or (state=='running' and (not paths or healthy<len(paths) or runtime.get('unavailable_links'))) or state=='failed'
        if issue:
            self.flash=not self.flash;icon=self.icons['problem' if self.flash else 'disconnected']
            title=f'GameBond · Network problem · {healthy}/{len(paths)} enabled links'
        elif state=='running':
            self.flash=False;icon=self.icons['connected'];title=f"GameBond · Connected · {runtime['peer'][0]} · {healthy}/{len(paths)} links"
        elif self.controller.busy or state in ('starting','connecting','stopping'):
            icon=self.icons['problem'];title='GameBond · Connecting / stopping'
        else:icon=self.icons['disconnected'];title='GameBond · Disconnected'
        self.tray.setIcon(icon);self.tray.setToolTip(title);self.status_icon.setPixmap(icon.pixmap(12,12))

    @pyqtSlot(bool)
    def _busy_changed(self,busy):
        if busy:self.problem=None
        self._update_status()

    @pyqtSlot(str)
    def _error(self,message):
        self.problem=message;self._quitting=False;self.show_dashboard();self._update_status()

    @pyqtSlot()
    def _tunnel_stopped(self):
        self.problem=None
        self.tray_quit.setText('Quit (stop tunnel)')
        if self._quitting:self._finish_close()

    def show_dashboard(self):
        if self.isMinimized():self.showNormal()
        else:self.show()
        self.raise_();self.activateWindow()

    def _tray_activated(self,reason):
        if reason in (QSystemTrayIcon.Trigger,QSystemTrayIcon.DoubleClick):self.show_dashboard()

    def toggle_maximized(self):
        self.showNormal() if self.isMaximized() else self.showMaximized()
        asset='window-restore-button.svg' if self.isMaximized() else 'window-expand-button.svg'
        self.maximize_button.setIcon(self.theme.icon('MainTopPanel/'+asset,size=12))

    def _dialog(self,dialog):
        self.show_dashboard();self.dialogs.append(dialog)
        dialog.saved.connect(self._settings_saved)
        dialog.finished.connect(lambda result:self.dialogs.remove(dialog) if dialog in self.dialogs else None)
        dialog.setAttribute(Qt.WA_DeleteOnClose);dialog.open()

    def open_applications(self):
        from .glass_settings import ApplicationsDialog
        self._dialog(ApplicationsDialog(self))

    def open_networks(self):
        from .glass_settings import NetworksDialog
        self._dialog(NetworksDialog(self.monitor_data.get('links',[]),self))

    def open_link_controls(self):
        from .glass_settings import LinkControlsDialog
        self._dialog(LinkControlsDialog(self.monitor_data.get('links',[]),self.runtime,self))

    @pyqtSlot(dict)
    def _settings_saved(self,config):
        self.config=config;self.pending_settings=True;self.settingsChanged.emit(config)
        if hasattr(self.dns,'update_config'):self.dns.update_config(config)
        self._update_networks();self._update_status()

    def _toast_activated(self,event):
        self.show_dashboard();self.select_tab(2)

    @pyqtSlot()
    def quit(self):
        if self._quitting:return
        self._quitting=True;self.tray_quit.setText('Stopping tunnel…')
        if not self.controller.stop():
            self._quitting=False;self.problem='Wait for the current connection action before quitting';self._update_status()

    @pyqtSlot()
    def reload_interface(self):
        self.reload_requested=True;self._finish_close()

    def _finish_close(self):
        if self._final_close:return
        self._final_close=True;self.tray_timer.stop();self.tray.hide();self.toasts.close()
        self.controller.shutdown()
        for panel in self.panels:
            if hasattr(panel,'shutdown'):panel.shutdown()
        self.close();QApplication.instance().quit()

    def closeEvent(self,event):
        if self._final_close:event.accept();return
        event.ignore()
        if self.tray_available:self.hide()
        else:self.quit()

    def nativeEvent(self,event_type,message):
        if os.name=='nt':
            from ctypes import wintypes
            msg=wintypes.MSG.from_address(int(message))
            if msg.message==0x0084:  # WM_NCHITTEST
                if not self.isMaximized():
                    get_rect=ctypes.windll.user32.GetWindowRect
                    get_rect.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.RECT)];get_rect.restype=wintypes.BOOL
                    rectangle=wintypes.RECT();get_rect(int(self.winId()),ctypes.byref(rectangle))
                    x=ctypes.c_short(msg.lParam&0xffff).value;y=ctypes.c_short((msg.lParam>>16)&0xffff).value
                    border=max(5,round(6*self.devicePixelRatioF()))
                    left=x<rectangle.left+border;right=x>=rectangle.right-border
                    top=y<rectangle.top+border;bottom=y>=rectangle.bottom-border
                    code=13 if top and left else 14 if top and right else 16 if bottom and left else 17 if bottom and right else 10 if left else 11 if right else 12 if top else 15 if bottom else None
                    if code:return True,code
                point=self.mapFromGlobal(QCursor.pos());child=self.childAt(point)
                if point.y()<84 and not isinstance(child,QAbstractButton):return True,2  # HTCAPTION
        return super().nativeEvent(event_type,message)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--tray',action='store_true');args=parser.parse_args(argv)
    if QApplication.instance() is None:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling,True);QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps,True)
    lease=AgentLease(ROOT) if os.name=='nt' else None
    if lease and not lease.owner:lease.close();return 0
    app=QApplication(sys.argv[:1]);app.setApplicationName('GameBond');app.setQuitOnLastWindowClosed(False);load_fonts()
    window=None
    try:
        window=GlassDashboard(lease=lease)
        if not args.tray or not window.tray_available:window.show()
        result=app.exec_()
    finally:
        if window and not window._final_close:window._finish_close()
        if lease:lease.close()
    if window and window.reload_requested:
        executable=Path(sys.executable);pythonw=executable.with_name('pythonw.exe')
        subprocess.Popen([str(pythonw if pythonw.exists() else executable),'-m','gamebond.glass_dashboard'],cwd=ROOT,creationflags=HIDDEN)
    return result


if __name__=='__main__':raise SystemExit(main())
