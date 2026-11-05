"""Qt5 resource and LAN panels backed by real, asynchronous providers.

Panels inherit the host application's palette/stylesheets. Object names and
``set_theme`` allow the GlassWire-style shell to supply recovered visual tokens.
No active discovery is started until the Scan button is pressed.
"""
from __future__ import annotations

from datetime import datetime
import threading
from pathlib import Path

from PyQt5.QtCore import QObject, Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QPainter, QPainterPath, QPen, QIcon, QPixmap
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QInputDialog,
    QHeaderView, QLabel, QLineEdit, QProgressBar, QPushButton, QSizePolicy,
    QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .hardware_monitor import HardwareSampler
from .network_scanner import DiscoveryJob, DeviceHistory, inventory


def _bytes(value, suffix=''):
    if value is None:
        return '—'
    value = float(value)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(value) < 1024 or unit == 'TB':
            return f'{value:.1f} {unit}{suffix}'
        value /= 1024


def _table(columns, name):
    table = QTableWidget(0, len(columns))
    table.setObjectName(name)
    table.setHorizontalHeaderLabels(columns)
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    table.setSelectionMode(QTableWidget.SingleSelection)
    table.setAlternatingRowColors(True)
    table.verticalHeader().hide()
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    table.setSortingEnabled(False)
    return table


def _rows(table, rows):
    table.setUpdatesEnabled(False)
    try:
        table.setRowCount(len(rows))
        for row_index, values in enumerate(rows):
            for column, value in enumerate(values):
                text=str(value);item=table.item(row_index,column)
                if item is None:
                    item=QTableWidgetItem(text);table.setItem(row_index,column,item)
                elif item.text()!=text:item.setText(text)
                if item.toolTip()!=text:item.setToolTip(text)
    finally:
        table.setUpdatesEnabled(True)


class _AsyncCall(QObject):
    """Daemon worker with queued Qt results and no UI work off the main thread."""
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, parent):
        super().__init__(parent)
        self.busy = False
        self.stopped = threading.Event()
        self.done.connect(self._done)
        self.failed.connect(self._failed)
        stopped = self.stopped
        parent.destroyed.connect(lambda: stopped.set())

    def start(self, function):
        if self.busy or self.stopped.is_set():
            return False
        self.busy = True
        def run():
            try:
                result = function()
                if not self.stopped.is_set():
                    self.done.emit(result)
            except Exception as exc:
                if not self.stopped.is_set():
                    try:
                        self.failed.emit(str(exc))
                    except RuntimeError:
                        pass  # Qt owner was deleted during a blocking provider call.
        threading.Thread(target=run, name='gamebond-monitor-provider', daemon=True).start()
        return True

    @pyqtSlot(object)
    def _done(self,result):self.busy=False

    @pyqtSlot(str)
    def _failed(self,message):self.busy=False

    def shutdown(self):
        self.stopped.set()


class ResourceChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('resourceHistoryChart')
        self.setMinimumSize(220, 110)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.history = []
        self.theme = {}

    def set_theme(self, theme):
        self.theme = dict(theme or {})
        self.update()

    def set_history(self, history):
        self.history = list(history[-120:])
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        background = QColor(self.theme.get('chart_background', self.palette().base().color().name()))
        painter.fillRect(self.rect(), background)
        area = self.rect().adjusted(38, 15, -12, -26)
        muted = QColor(self.theme.get('muted', self.palette().text().color().name()))
        grid = QColor(self.theme.get('grid', '#d9dee5'))
        painter.setPen(QPen(grid, 1, Qt.DotLine))
        for percent in (0, 50, 100):
            y = area.bottom() - area.height() * percent / 100
            painter.drawLine(area.left(), int(y), area.right(), int(y))
            painter.setPen(muted)
            painter.drawText(2, int(y)+4, f'{percent}%')
            painter.setPen(QPen(grid, 1, Qt.DotLine))
        if len(self.history) > 1:
            first = self.history[0]['monotonic_time']
            elapsed = max(.001, self.history[-1]['monotonic_time']-first)
            for key, color in (('cpu_percent', self.theme.get('cpu', '#31a8d9')),
                               ('memory_percent', self.theme.get('memory', '#72bc65'))):
                path = QPainterPath()
                connected = False
                for sample in self.history:
                    value = sample.get(key)
                    if value is None:
                        connected = False
                        continue
                    x = area.left() + area.width() * (sample['monotonic_time']-first) / elapsed
                    y = area.bottom() - area.height()*max(0, min(100, value))/100
                    if connected:
                        path.lineTo(x, y)
                    else:
                        path.moveTo(x, y); connected = True
                painter.setPen(QPen(QColor(color), 2))
                painter.drawPath(path)
        painter.setPen(muted)
        painter.drawText(area.left(), self.height()-6, 'CPU and memory · recent samples')


class HardwareGraphs(QWidget):
    """GlassWire-style five-minute CPU, memory, disk and GPU graph stack."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('hardwareGraphs')
        self.setMinimumSize(320, 240)
        self.history=[]; self.theme={};self.gpu_status='not_sampled'

    def set_theme(self, theme):
        self.theme=dict(theme or {}); self.update()

    def set_history(self, history):
        latest=history[-1]['monotonic_time'] if history else 0
        self.history=[row for row in history if row['monotonic_time']>=latest-300]
        self.update()

    def paintEvent(self, event):
        painter=QPainter(self); painter.setRenderHint(QPainter.Antialiasing)
        background=QColor(self.theme.get('graph_bg',self.theme.get('chart_background','#e9f8fa')))
        primary=QColor(self.theme.get('primary','#6d8ced'))
        muted=QColor(self.theme.get('graph_label','#a0a9aa'))
        grid=QColor(self.theme.get('graph_grid','#d8e4e7'))
        painter.fillRect(self.rect(),background)
        timeline_height=27; row_height=(self.height()-timeline_height)/4
        latest=self.history[-1]['monotonic_time'] if self.history else 0
        rows=(('CPU','cpu_percent'),('Memory','memory_percent'),('Disk transfer rate','disk'),('GPU','gpu_percent'))
        for index,(title,key) in enumerate(rows):
            top=index*row_height; bottom=(index+1)*row_height
            points=[]
            for sample in self.history:
                if key=='disk':
                    read,write=sample.get('disk_read_bytes_s'),sample.get('disk_write_bytes_s')
                    value=None if read is None and write is None else (read or 0)+(write or 0)
                else:value=sample.get(key)
                points.append((sample['monotonic_time'],value))
            maximum=100 if key!='disk' else max(1024,max((v for _,v in points if v is not None),default=0)*1.15)
            painter.setPen(muted)
            painter.drawText(15,int(top)+22,title)
            scale=f'{maximum:.0f}%' if key!='disk' else _bytes(maximum,'/s')
            painter.drawText(self.width()-125,int(top)+22,110,18,Qt.AlignRight,scale)
            baseline=bottom-1; plot_top=top+30; height=max(1,baseline-plot_top)
            painter.setPen(QPen(grid,1)); painter.drawLine(0,int(baseline),self.width(),int(baseline))
            path=QPainterPath(); fill=QPainterPath(); started=False; first_x=None; last_x=None
            for timestamp,value in points:
                if value is None:
                    started=False; continue
                x=max(0,min(self.width(),self.width()*(timestamp-(latest-300))/300))
                y=baseline-height*max(0,min(maximum,value))/maximum
                if not started:
                    path.moveTo(x,y); fill.moveTo(x,baseline);fill.lineTo(x,y);started=True
                    if first_x is None:first_x=x
                else:path.lineTo(x,y);fill.lineTo(x,y)
                last_x=x
            if last_x is not None:
                fill.lineTo(last_x,baseline);fill.closeSubpath()
                shade=QColor(primary);shade.setAlpha(36);painter.fillPath(fill,shade)
                painter.setPen(QPen(primary,1.2));painter.drawPath(path)
            elif key=='gpu_percent':
                painter.setPen(muted);painter.drawText(15,int(top)+43,'Waiting for GPU sample' if self.gpu_status=='not_sampled' else 'GPU counters unavailable')
        painter.fillRect(0,self.height()-timeline_height,self.width(),timeline_height,QColor(self.theme.get('timeline_bg','#ffffff')))
        painter.setPen(QColor(self.theme.get('timeline_text','#8b9198')))
        for seconds in range(0,301,60):
            x=int(self.width()*seconds/300)
            painter.drawLine(x,self.height()-timeline_height,x,self.height()-timeline_height+5)
            text='Now' if seconds==300 else f'{5-seconds//60} min'
            painter.drawText(max(6,min(self.width()-45,x+5)),self.height()-7,text)


class HardwarePanel(QWidget):
    snapshotReady=pyqtSignal(object)

    def __init__(self,parent=None,*,sampler=None,sample_interval_ms=1500,theme=None,autostart=True):
        super().__init__(parent)
        self.setObjectName('hardwareResourcesPanel')
        self.sampler=sampler or HardwareSampler()
        provider=self.sampler
        if hasattr(provider,'shutdown'):self.destroyed.connect(lambda:provider.shutdown())
        self.last_snapshot=None;self.closed=False;self._active=True;self._autostart=autostart
        self.worker=_AsyncCall(self);self.worker.done.connect(self._sample_ready);self.worker.failed.connect(self._sample_failed)
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0);layout.setSpacing(0)
        self.chart=HardwareGraphs();layout.addWidget(self.chart,1)
        self.details=QFrame();self.details.setObjectName('hardwareDetails');details_layout=QHBoxLayout(self.details)
        self.processes_table=_table(['Application','PID','CPU','Memory','Threads'],'hardwareProcessesTable')
        self.disks_table=_table(['Drive','Used','Free','Usage'],'hardwareDisksTable')
        self.adapters_table=_table(['Adapter','Receive','Send'],'hardwareAdaptersTable')
        details_layout.addWidget(self.processes_table,2);details_layout.addWidget(self.disks_table);details_layout.addWidget(self.adapters_table)
        self.details.setFixedHeight(210);self.details.hide();layout.addWidget(self.details)
        self.footer=QFrame();self.footer.setObjectName('hardwareStatsFooter')
        self.footer.setAutoFillBackground(True)
        footer_layout=QGridLayout(self.footer);footer_layout.setContentsMargins(18,15,18,8);footer_layout.setHorizontalSpacing(18)
        self.stat_values={}
        for column,(key,title) in enumerate((('cpu','CPU Usage'),('memory','Memory Usage'),('read','Disk Read'),
                ('write','Disk Write'),('gpu','GPU Usage'),('gpu_memory','GPU Memory'))):
            heading=QLabel(title);heading.setObjectName('hardwareStatTitle')
            value=QLabel('—');value.setObjectName('hardwareStatValue')
            font=value.font();font.setPointSize(max(18,font.pointSize()+8));value.setFont(font)
            footer_layout.addWidget(heading,0,column);footer_layout.addWidget(value,1,column);footer_layout.setColumnStretch(column,1)
            self.stat_values[key]=value
        self.status=QLabel('Waiting for a resource sample…');self.status.setObjectName('hardwareStatus');self.status.setWordWrap(True)
        footer_layout.addWidget(self.status,2,0,1,6);layout.addWidget(self.footer)
        self.cpu_value=self.stat_values['cpu'];self.memory_value=self.stat_values['memory']
        self.refresh_button=QPushButton('Refresh',self);self.refresh_button.hide();self.refresh_button.clicked.connect(self.refresh)
        self.timer=QTimer(self);self.timer.setInterval(max(500,int(sample_interval_ms)));self.timer.timeout.connect(self.refresh)
        self.set_theme(theme)
        self.setContextMenuPolicy(Qt.CustomContextMenu);self.customContextMenuRequested.connect(self._context_menu)
        if autostart:self.timer.start();QTimer.singleShot(0,self.refresh)

    def set_theme(self,theme):
        theme=dict(theme or {});self.chart.set_theme(theme)
        from PyQt5.QtGui import QPalette
        palette=self.footer.palette();palette.setColor(QPalette.Window,QColor(theme.get('footer_bg','#ffffff')))
        self.footer.setPalette(palette)

    def show_details(self,visible=True):self.details.setVisible(bool(visible))

    def _context_menu(self,position):
        from PyQt5.QtWidgets import QMenu
        menu=QMenu(self)
        menu.addAction('Refresh resource sample',self.refresh)
        detail=menu.addAction('Show process and device details');detail.setCheckable(True);detail.setChecked(self.details.isVisible())
        detail.triggered.connect(self.show_details)
        menu.exec_(self.mapToGlobal(position))

    def set_active(self,active):
        previous=self._active;self._active=bool(active)
        if not self._active:self.timer.stop()
        elif not previous and not self.closed:
            if self._autostart:self.timer.start()
            self.refresh()

    @pyqtSlot()
    def refresh(self):
        if self.closed or not self._active or self.worker.busy:return
        self.refresh_button.setEnabled(False);self.worker.start(self.sampler.sample)

    @pyqtSlot(object)
    def _sample_ready(self,snapshot):
        if self.closed:return
        self.last_snapshot=snapshot;cpu,memory=snapshot['cpu'],snapshot['memory'];gpu=snapshot.get('gpu',{})
        self.chart.gpu_status=gpu.get('status','available' if gpu.get('available') else 'unavailable')
        self.stat_values['cpu'].setText('—' if cpu['percent'] is None else f"{cpu['percent']:.0f}%")
        self.stat_values['memory'].setText(f"{memory['percent']:.0f}%")
        disk_rates=[row['rates'] for row in snapshot.get('disk_io',{}).values() if row.get('rates') is not None]
        self.stat_values['read'].setText(_bytes(sum(row['read_bytes'] for row in disk_rates),'/s') if disk_rates else '—')
        self.stat_values['write'].setText(_bytes(sum(row['write_bytes'] for row in disk_rates),'/s') if disk_rates else '—')
        self.stat_values['gpu'].setText('—' if gpu.get('percent') is None else f"{gpu['percent']:.0f}%")
        self.stat_values['gpu_memory'].setText(_bytes(gpu.get('dedicated_used_bytes')))
        self.stat_values['gpu'].setToolTip('Busiest GPU engine across adapters' if gpu.get('available') else 'Windows GPU counters unavailable')
        self.stat_values['gpu_memory'].setToolTip('Dedicated GPU memory currently used; capacity is not inferred')
        disks=snapshot.get('disks',[])
        _rows(self.disks_table,[(row.get('mountpoint',row.get('device','')),_bytes(row.get('used_bytes')),_bytes(row.get('free_bytes')),
                row.get('error',f"{row.get('percent',0):.1f}%")) for row in disks])
        processes=snapshot.get('processes',[])
        _rows(self.processes_table,[(row['name'],row['pid'],'—' if row['cpu_percent'] is None else f"{row['cpu_percent']:.1f}%",
                _bytes(row['resident_bytes']),row.get('threads') or '—') for row in processes])
        for index,row in enumerate(processes):self.processes_table.item(index,0).setToolTip(row.get('executable') or row['name'])
        _rows(self.adapters_table,[(row['name'],_bytes((row.get('rates') or {}).get('received_bytes'),'/s'),
                _bytes((row.get('rates') or {}).get('sent_bytes'),'/s')) for row in snapshot.get('adapters',[])])
        self.chart.set_history(snapshot.get('history',[]))
        stamp=datetime.fromtimestamp(snapshot['observed_at']).strftime('%H:%M:%S')
        text=f'Updated {stamp}'
        if snapshot.get('errors'):text+=' · '+'; '.join(snapshot['errors'])
        self.status.setText(text);self.refresh_button.setEnabled(True);self.snapshotReady.emit(snapshot)

    @pyqtSlot(str)
    def _sample_failed(self,message):
        if not self.closed:self.status.setText('Resource sampling failed: '+message);self.refresh_button.setEnabled(True)

    def shutdown(self):
        self.closed=True;self.timer.stop();self.worker.shutdown()
        if hasattr(self.sampler,'shutdown'):self.sampler.shutdown()

    def closeEvent(self,event):self.shutdown();super().closeEvent(event)


class NetworkScannerPanel(QWidget):
    inventoryReady = pyqtSignal(object)
    discoveryFinished = pyqtSignal(object)
    deviceSelected = pyqtSignal(object)

    def __init__(self, parent=None, *, inventory_provider=inventory, scan_factory=DiscoveryJob,
                 theme=None, autostart=True,history=None):
        super().__init__(parent)
        self.setObjectName('networkScannerPanel')
        self.inventory_provider, self.scan_factory = inventory_provider, scan_factory
        self.closed = False; self.last_inventory = None; self.scan_job = None
        self._pending_job = None; self._scan_starting = False; self._scan_cancel = threading.Event()
        self._reported_finished = False; self._devices = []
        def abandoned():
            self._scan_cancel.set()
            job=self.scan_job or self._pending_job
            if job:job.cancel()
        self.destroyed.connect(abandoned)
        self._history_error=None
        try:self.history=history or DeviceHistory(Path(__file__).resolve().parents[1]/'.runtime/network-devices.json')
        except (OSError,ValueError) as exc:self.history=DeviceHistory();self._history_error=str(exc)
        self.icon_provider=None
        self._active_history={}
        self.history_worker=_AsyncCall(self);self.history_worker.done.connect(self._history_ready)
        self.history_worker.failed.connect(self._history_failed)
        self.inventory_worker = _AsyncCall(self)
        self.inventory_worker.done.connect(self._inventory_ready)
        self.inventory_worker.failed.connect(self._inventory_failed)
        self.start_worker = _AsyncCall(self)
        self.start_worker.done.connect(self._scan_started)
        self.start_worker.failed.connect(self._scan_failed)
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0);layout.setSpacing(0)
        self.toolbar=QFrame();self.toolbar.setObjectName('scannerToolbar');self.toolbar.setFixedHeight(60)
        header=QHBoxLayout(self.toolbar);header.setContentsMargins(14,10,14,10);header.setSpacing(12)
        self.adapter_combo = QComboBox(); self.adapter_combo.setObjectName('scannerAdapterCombo')
        self.adapter_combo.setMinimumWidth(170);self.adapter_combo.setMaximumWidth(250)
        self.adapter_combo.currentIndexChanged.connect(self._adapter_changed)
        header.addWidget(self.adapter_combo)
        self.scan_button = QPushButton('Scan'); self.scan_button.setObjectName('scannerScanButton')
        self.scan_button.setMinimumWidth(70);self.scan_button.clicked.connect(self.start_scan);header.addWidget(self.scan_button)
        self.scanned_label=QLabel('Scanned: —');self.scanned_label.setObjectName('scannerScannedLabel');header.addWidget(self.scanned_label)
        header.addStretch()
        self.search_edit=QLineEdit();self.search_edit.setObjectName('scannerSearchEdit');self.search_edit.setPlaceholderText('Search')
        self.search_edit.setMaximumWidth(220);self.search_edit.setClearButtonEnabled(True);self.search_edit.textChanged.connect(self._render_devices)
        header.addWidget(self.search_edit)
        self.auto_scan=QCheckBox('Auto-scan');self.auto_scan.setObjectName('scannerAutoScan');header.addWidget(self.auto_scan)
        self.auto_timer=QTimer(self);self.auto_timer.setInterval(60000);self.auto_timer.timeout.connect(self.start_scan)
        self.auto_scan.toggled.connect(self._auto_toggled)
        self.refresh_button = QPushButton('Refresh devices'); self.refresh_button.setObjectName('scannerRefreshButton')
        self.refresh_button.clicked.connect(self.refresh_inventory);self.refresh_button.hide()
        layout.addWidget(self.toolbar)
        self.subtitle = QLabel('Local devices from the Windows neighbor cache. Scan explicitly to test ICMP responses.')
        self.subtitle.setWordWrap(True); self.subtitle.setObjectName('panelSubtitle');self.subtitle.hide()
        self.subnet_edit = QLineEdit(); self.subnet_edit.setObjectName('scannerSubnetEdit')
        self.subnet_edit.setPlaceholderText('192.168.1.0/24');self.subnet_edit.hide()
        actions = QHBoxLayout()
        self.cancel_button = QPushButton('Cancel scan'); self.cancel_button.setObjectName('scannerCancelButton')
        self.cancel_button.clicked.connect(self.cancel_scan); self.cancel_button.setEnabled(False)
        actions.addWidget(self.cancel_button); actions.addStretch()
        self.progress = QProgressBar(); self.progress.setObjectName('scannerProgress'); self.progress.setRange(0, 1); self.progress.setValue(0)
        actions.addWidget(self.progress,1)
        self.progress_bar=QFrame();self.progress_bar.setLayout(actions);self.progress_bar.hide();layout.addWidget(self.progress_bar)
        self.devices_table = _table(['','Type','Name','Description','Location','System','IP','MAC Address','Last Seen','First Seen'], 'scannerDevicesTable')
        self.devices_table.verticalHeader().setDefaultSectionSize(56);self.devices_table.horizontalHeader().setFixedHeight(30)
        for column,width in enumerate((24,44,150,170,90,90,120,150,130,130)):self.devices_table.setColumnWidth(column,width)
        self.devices_table.setShowGrid(False)
        self.devices_table.itemSelectionChanged.connect(self._device_selected)
        layout.addWidget(self.devices_table, 1)
        self.status = QLabel('Waiting for passive network inventory…'); self.status.setWordWrap(True)
        self.status.setObjectName('scannerStatus'); layout.addWidget(self.status)
        self.limit_note = QLabel('Discovery stays on the chosen private local subnet: at most 256 addresses. Devices may block ICMP; no reply does not mean offline.')
        self.limit_note.setWordWrap(True); self.limit_note.setObjectName('scannerLimitNote'); layout.addWidget(self.limit_note)
        self.poll_timer = QTimer(self); self.poll_timer.setInterval(150); self.poll_timer.timeout.connect(self._poll_scan)
        self.setContextMenuPolicy(Qt.CustomContextMenu);self.customContextMenuRequested.connect(self._context_menu)
        self.set_theme(theme); self._update_controls()
        if autostart:
            QTimer.singleShot(0, self.refresh_inventory)

    def set_theme(self, theme):
        # Host shell can target panel/table/button object names through QSS.
        self.theme = dict(theme or {})
        self.devices_table.setStyleSheet('QTableWidget {background:'+self.theme.get('table_bg','#ffffff')+
            ';alternate-background-color:'+self.theme.get('table_alt','#f7f7f7')+';border:0;} QHeaderView::section {background:'+
            self.theme.get('table_header_bg','#ffffff')+';color:'+self.theme.get('table_header_text','#6a7179')+
            ';border:0;border-bottom:1px solid '+self.theme.get('table_border','#dddddd')+';padding:5px;}')

    def set_icon_provider(self,provider):
        """Optional callable(device_dict)->QIcon supplied by the asset-aware shell."""
        self.icon_provider=provider;self._render_devices()

    def _context_menu(self,position):
        from PyQt5.QtWidgets import QMenu
        menu=QMenu(self);menu.addAction('Refresh cached devices',self.refresh_inventory)
        action=menu.addAction('Change scan subnet…',self._change_subnet);action.setEnabled(not self._active())
        menu.exec_(self.mapToGlobal(position))

    def _change_subnet(self):
        value,accepted=QInputDialog.getText(self,'Local discovery subnet','Private subnet on the selected adapter:',text=self.subnet_edit.text())
        if accepted:self.subnet_edit.setText(value.strip());self.scan_button.setToolTip('Scan '+value.strip())

    @pyqtSlot(bool)
    def _auto_toggled(self,enabled):
        if enabled:
            self.auto_timer.start();self.start_scan()
        else:self.auto_timer.stop()

    def _active(self):
        return self._scan_starting or (self.scan_job is not None and self.scan_job.snapshot()['state'] in ('ready','running'))

    def _update_controls(self):
        active = self._active()
        available = self.adapter_combo.currentData() is not None
        self.adapter_combo.setEnabled(not active)
        self.subnet_edit.setEnabled(not active)
        self.scan_button.setEnabled(available and not active and not self.inventory_worker.busy)
        self.cancel_button.setEnabled(active)
        self.progress_bar.setVisible(active)
        self.refresh_button.setEnabled(not active and not self.inventory_worker.busy)
        self.auto_scan.setEnabled(available or self.auto_scan.isChecked())

    @pyqtSlot()
    def refresh_inventory(self):
        if self.closed or self.inventory_worker.busy or self._active():
            return
        self.status.setText('Reading local adapters and neighbor cache…')
        def collect():
            snapshot=dict(self.inventory_provider())
            snapshot['devices']=self.history.observe(snapshot.get('devices',[]),snapshot.get('observed_at'))
            return snapshot
        self.inventory_worker.start(collect); self._update_controls()

    @pyqtSlot(object)
    def _inventory_ready(self, snapshot):
        if self.closed:
            return
        self.last_inventory = snapshot
        previous = self.adapter_combo.currentData()
        previous_key = None if previous is None else (previous['index'], previous['address'])
        self.adapter_combo.blockSignals(True); self.adapter_combo.clear()
        for adapter in snapshot.get('adapters', []):
            if not adapter.get('up'):
                continue
            self.adapter_combo.addItem(f"{adapter['name']} — {adapter['address']}", adapter)
        selected = 0
        for index in range(self.adapter_combo.count()):
            adapter = self.adapter_combo.itemData(index)
            if (adapter['index'],adapter['address']) == previous_key:
                selected = index; break
        self.adapter_combo.setCurrentIndex(selected if self.adapter_combo.count() else -1)
        self.adapter_combo.blockSignals(False)
        self._adapter_changed()
        self.status.setText(f"Passive inventory: {len(snapshot.get('devices', []))} cached devices · no active scan has been started" if self.scan_job is None else 'Neighbor cache refreshed after discovery')
        if self._history_error:self.status.setText(self.status.text()+' · History unavailable: '+self._history_error)
        # Signal delivery can precede the worker's final busy=False assignment.
        QTimer.singleShot(0, self._update_controls)
        self.inventoryReady.emit(snapshot)

    @pyqtSlot(str)
    def _inventory_failed(self, message):
        if not self.closed:
            self.status.setText('Network inventory failed: '+message)
            QTimer.singleShot(0,self._update_controls)

    @pyqtSlot()
    def _adapter_changed(self):
        adapter = self.adapter_combo.currentData()
        if adapter:
            self.subnet_edit.setText(adapter.get('discovery_subnet',adapter['subnet']))
            self.scan_button.setToolTip('Scan '+self.subnet_edit.text()+' using '+adapter['address'])
        self._render_devices(); self._update_controls()

    def _render_devices(self):
        adapter = self.adapter_combo.currentData()
        devices = {}
        if adapter and self.last_inventory:
            for device in self.last_inventory.get('devices', []):
                if device['interface_index'] == adapter['index']:
                    row = dict(device); row['observation'] = 'Neighbor cache: '+device['state']; row['rtt_ms'] = None
                    devices[row['address']] = row
        if adapter and self.scan_job:
            scan = self.scan_job.snapshot()
            if scan['interface_index'] == adapter['index']:
                for result in scan['results']:
                    if not result.get('responded') and result['address'] not in devices:
                        continue
                    row = devices.setdefault(result['address'],dict(address=result['address'],hostname=None,mac=None,vendor=None))
                    row['observation'] = 'ICMP response' if result.get('responded') else 'No ICMP reply; cached device'
                    row['rtt_ms'] = result.get('rtt_ms')
                    for key in ('first_seen','last_seen'):
                        if key in self._active_history.get(result['address'],{}):row[key]=self._active_history[result['address']][key]
        import ipaddress
        query=self.search_edit.text().strip().casefold()
        self._devices = [row for row in sorted(devices.values(),key=lambda row:int(ipaddress.IPv4Address(row['address'])))
            if not query or query in ' '.join(str(row.get(key) or '') for key in ('address','hostname','mac','vendor','description','system')).casefold()]
        def stamp(value):return datetime.fromtimestamp(value).strftime('%d %b %H:%M:%S') if value is not None else ''
        _rows(self.devices_table, [('', '',row.get('hostname') or 'Unavailable',
            row.get('description') or '',row.get('location') or '',row.get('system') or '',row['address'],row.get('mac') or '',
            stamp(row.get('last_seen')),stamp(row.get('first_seen'))) for row in self._devices])
        for index,row in enumerate(self._devices):
            reachable=row.get('rtt_ms') is not None or row.get('reachable_now')
            dot=QPixmap(12,12);dot.fill(Qt.transparent);painter=QPainter(dot);painter.setRenderHint(QPainter.Antialiasing)
            color=QColor('#6ad68c' if reachable else '#a8adb5');painter.setPen(QPen(color,1))
            painter.setBrush(color if reachable else Qt.NoBrush);painter.drawEllipse(2,2,7,7);painter.end()
            status=self.devices_table.item(index,0);status.setIcon(QIcon(dot));status.setData(Qt.AccessibleTextRole,'Reachable' if reachable else 'Cached')
            status.setToolTip(row['observation'])
            for column in (8,9):self.devices_table.item(index,column).setToolTip('First/last observation by GameBond. Neighbor-cache observations do not prove current connectivity.')
            if self.icon_provider:
                icon=self.icon_provider(dict(row))
                if isinstance(icon,QIcon):self.devices_table.item(index,1).setIcon(icon)

    @pyqtSlot()
    def start_scan(self):
        adapter = self.adapter_combo.currentData()
        if self.closed or self._active() or self.inventory_worker.busy or adapter is None:
            return
        subnet = self.subnet_edit.text().strip(); source = adapter['address']; index = adapter['index']
        self._scan_cancel = threading.Event(); cancellation = self._scan_cancel
        self._active_history={}
        self._scan_starting = True; self.scan_job = None; self._reported_finished = False
        self.status.setText('Validating the selected local subnet and adapter…')
        self._update_controls()
        def prepare():
            job = self.scan_factory(subnet,source,index)
            self._pending_job = job
            if cancellation.is_set():job.cancel()
            job.start()
            return job
        self.start_worker.start(prepare)

    @pyqtSlot(object)
    def _scan_started(self, job):
        self._scan_starting = False; self.scan_job = job
        if self.closed:
            job.cancel(); return
        if self._scan_cancel.is_set():job.cancel()
        self.poll_timer.start(); self._poll_scan()

    @pyqtSlot(str)
    def _scan_failed(self, message):
        self._scan_starting = False
        if not self.closed:
            self.auto_scan.setChecked(False)
            self.status.setText('Discovery could not start: '+message); self._update_controls()

    @pyqtSlot()
    def cancel_scan(self):
        self.auto_scan.setChecked(False)
        self._scan_cancel.set()
        job = self.scan_job or self._pending_job
        if job:job.cancel()
        self.status.setText('Cancelling discovery…')

    @pyqtSlot()
    def _poll_scan(self):
        if self.closed or self.scan_job is None:
            return
        snapshot = self.scan_job.snapshot()
        self.progress.setRange(0,max(1,snapshot['total'])); self.progress.setValue(snapshot['completed'])
        responsive = sum(bool(row.get('responded')) for row in snapshot['results'])
        self.status.setText(f"{snapshot['state'].capitalize()} · {snapshot['completed']}/{snapshot['total']} tested · {responsive} ICMP responses")
        if snapshot.get('errors'):
            self.status.setText(self.status.text()+' · '+snapshot['errors'][0])
        self._render_devices(); self._update_controls()
        if snapshot['state'] in ('completed','cancelled','failed'):
            self.poll_timer.stop()
            self.scanned_label.setText('Scanned: '+datetime.fromtimestamp(snapshot.get('finished_at') or datetime.now().timestamp()).strftime('%d %b %H:%M:%S'))
            if not self._reported_finished:
                self._reported_finished = True; self.discoveryFinished.emit(snapshot)
                known={row['address']:row for row in self._devices}
                observations=[dict(address=row['address'],interface_index=snapshot['interface_index'],mac=known.get(row['address'],{}).get('mac'))
                    for row in snapshot['results'] if row.get('responded')]
                if observations:self.history_worker.start(lambda:self.history.observe(observations,snapshot.get('finished_at')))

    @pyqtSlot(object)
    def _history_ready(self,rows):
        self._active_history={row['address']:row for row in rows}
        if not self.closed:self._render_devices()

    @pyqtSlot(str)
    def _history_failed(self,message):
        if not self.closed:self.status.setText(self.status.text()+' · Device history: '+message)

    @pyqtSlot()
    def _device_selected(self):
        row = self.devices_table.currentRow()
        if 0 <= row < len(self._devices):self.deviceSelected.emit(dict(self._devices[row]))

    def shutdown(self):
        self.closed = True; self._scan_cancel.set(); self.poll_timer.stop();self.auto_timer.stop()
        job = self.scan_job or self._pending_job
        if job:job.cancel()
        self.inventory_worker.shutdown(); self.start_worker.shutdown()
        self.history_worker.shutdown()

    def closeEvent(self, event):
        self.shutdown(); super().closeEvent(event)
