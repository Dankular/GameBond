"""GlassWire-layout traffic views driven by real tunnel application counters."""
from collections import deque
from datetime import datetime
from pathlib import Path
import time

from PyQt5.QtCore import Qt,QRectF,pyqtSignal
from PyQt5.QtGui import QPainter,QPainterPath,QLinearGradient,QColor,QPen,QFont
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QComboBox,QStackedWidget,
    QTableWidget,QTableWidgetItem,QHeaderView,QFileIconProvider,QDialog,QDialogButtonBox,QListWidget,QListWidgetItem)
from PyQt5.QtCore import QFileInfo

from .glass_theme import GlassTheme
from .widget_data import TunnelRateSampler,human_bytes


class TrafficGraph(QWidget):
    def __init__(self,theme=None,parent=None):
        super().__init__(parent);self.theme=theme or GlassTheme();self.samples=deque(maxlen=3600);self.window=300
        self.setMinimumHeight(180)

    def append(self,down,up,timestamp=None):
        self.samples.append((timestamp or time.time(),max(0,down),max(0,up)));self.update()

    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.Antialiasing);p.fillRect(self.rect(),self.theme.color('graph_bg'))
        area=QRectF(0,40,self.width(),max(1,self.height()-65));now=time.time()
        samples=[s for s in self.samples if s[0]>=now-self.window]
        ceiling=max(125000,max((max(s[1],s[2]) for s in samples),default=0)*1.15)
        p.setPen(self.theme.color('graph_level_line'));p.drawLine(16,40,self.width()-16,40)
        p.setPen(self.theme.color('graph_level_txt'));p.drawText(16,28,f'{human_bytes(ceiling)}/s')
        if not samples:
            p.drawText(self.rect(),Qt.AlignCenter,'Waiting for tunnel traffic');return
        step=max(1,len(samples)//max(1,self.width()))
        displayed=samples[::step]
        if displayed[-1]!=samples[-1]:displayed.append(samples[-1])
        for index,start,end in ((1,'graph_in_fill_s','graph_in_fill_e'),(2,'graph_out_fill_s','graph_out_fill_e')):
            points=[(max(0,min(area.width(),(stamp-(now-self.window))/self.window*area.width())),area.bottom()-value[index]/ceiling*area.height())
                    for value in displayed for stamp in [value[0]]]
            path=QPainterPath();path.moveTo(points[0][0],area.bottom());path.lineTo(*points[0])
            for x,y in points[1:]:path.lineTo(x,y)
            path.lineTo(points[-1][0],area.bottom());path.closeSubpath()
            gradient=QLinearGradient(0,area.top(),0,area.bottom());gradient.setColorAt(0,self.theme.color(start));gradient.setColorAt(1,self.theme.color(end))
            p.fillPath(path,gradient)
        p.setPen(self.theme.color('graph_timeline_txt'))
        for fraction in (0,.25,.5,.75,1):
            x=int(12+fraction*(self.width()-90));stamp=now-self.window+fraction*self.window
            p.drawText(x,self.height()-7,datetime.fromtimestamp(stamp).strftime('%H:%M:%S'))


class TrafficPanel(QWidget):
    def __init__(self,parent=None,theme=None):
        super().__init__(parent);self.theme=theme or GlassTheme();self.rates=TunnelRateSampler();self.pid=None
        self.previous={};self.rows=[];self.filter_paths=set();self.runtime=None;self.last_sample=0
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0);layout.setSpacing(0)
        toolbar=QWidget();toolbar.setStyleSheet(f'background:{self.theme.css("actionbar_bg")};');bar=QHBoxLayout(toolbar);bar.setContentsMargins(16,12,16,12)
        filter_button=QPushButton('Filter');filter_button.setIcon(self.theme.icon('TrafficPage/ic-filter.svg'));filter_button.clicked.connect(self.filter_apps);bar.addWidget(filter_button);bar.addStretch()
        graph=QPushButton();table=QPushButton();graph.setIcon(self.theme.icon('TrafficPage/ic-actionabar-graph.svg'));table.setIcon(self.theme.icon('TrafficPage/ic-actionbar-usage.svg'));graph.setToolTip('Traffic graph');table.setToolTip('Applications and hosts')
        graph.clicked.connect(lambda:self.views.setCurrentIndex(0));table.clicked.connect(lambda:self.views.setCurrentIndex(1));bar.addWidget(graph);bar.addWidget(table)
        bar.addStretch();self.period=QComboBox();self.period.addItems(['5 Minutes','15 Minutes','1 Hour']);self.period.currentIndexChanged.connect(self.change_period);bar.addWidget(self.period)
        layout.addWidget(toolbar)
        self.views=QStackedWidget();self.graph=TrafficGraph(self.theme);self.views.addWidget(self.graph)
        self.tables=QWidget();columns=QHBoxLayout(self.tables);columns.setContentsMargins(16,12,16,12)
        self.app_table=self.make_table(['Apps','Downloaded','Uploaded']);self.host_table=self.make_table(['Hosts','Application']);self.protocol_table=self.make_table(['Traffic Type','Connections'])
        columns.addWidget(self.app_table,2);columns.addWidget(self.host_table,2);columns.addWidget(self.protocol_table,1);self.views.addWidget(self.tables);layout.addWidget(self.views,1)
        self.views.currentChanged.connect(self._render_tables)
        footer=QWidget();footer.setMinimumHeight(90);footer.setStyleSheet(f'background:{self.theme.css("gw_mainbg")};border-top:1px solid {self.theme.css("graph_bottomline")};')
        summary=QHBoxLayout(footer);summary.setContentsMargins(30,14,30,14)
        self.down=QLabel('↓  —');self.total=QLabel('—');self.up=QLabel('↑  —');self.extra=QLabel('No tunnel running')
        self.total.setStyleSheet('font-size:23px;font-family:Oswald;color:#5e6b74;')
        for label in (self.down,self.total,self.up):summary.addWidget(label)
        summary.addSpacing(25);summary.addWidget(self.extra,1);layout.addWidget(footer)
        self.caption=QLabel('Application payload through your VPS');self.caption.setStyleSheet('padding:6px 16px;color:#8f9099;font-size:10px;');layout.addWidget(self.caption)
        self.icon_provider=QFileIconProvider();self.icons={}

    def make_table(self,headers):
        table=QTableWidget(0,len(headers));table.setHorizontalHeaderLabels(headers);table.setShowGrid(False);table.setAlternatingRowColors(True)
        table.verticalHeader().hide();table.setEditTriggers(QTableWidget.NoEditTriggers);table.setSelectionBehavior(QTableWidget.SelectRows)
        table.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        return table

    def change_period(self,index):self.graph.window=(300,900,3600)[index];self.graph.update()

    def filter_apps(self):
        dialog=QDialog(self);dialog.setWindowTitle('Filter tunnel applications');box=QVBoxLayout(dialog)
        box.addWidget(QLabel('Leave all unchecked to include every routed application.'))
        listing=QListWidget();box.addWidget(listing)
        seen=set()
        for row in self.rows:
            path=row['path']
            if path in seen:continue
            seen.add(path);item=QListWidgetItem(row.get('name') or Path(path).name);item.setData(Qt.UserRole,path)
            item.setFlags(item.flags()|Qt.ItemIsUserCheckable);item.setCheckState(Qt.Checked if path in self.filter_paths else Qt.Unchecked);listing.addItem(item)
        buttons=QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel);buttons.accepted.connect(dialog.accept);buttons.rejected.connect(dialog.reject);box.addWidget(buttons)
        if dialog.exec_()==QDialog.Accepted:
            self.filter_paths={listing.item(i).data(Qt.UserRole) for i in range(listing.count()) if listing.item(i).checkState()==Qt.Checked}
            self.graph.samples.clear();self.previous.clear()

    def update_runtime(self,runtime):
        self.runtime=runtime;now=time.monotonic()
        if now-self.last_sample<.8:return
        self.last_sample=now;rates=self.rates.sample(runtime,now)
        if not runtime:
            self.rows=[];self._render_tables()
            self.caption.setText('No tunnel running');self.down.setText('↓  —');self.up.setText('↑  —');self.total.setText('—');self.extra.setText('Disconnected');return
        if runtime['pid']!=self.pid:
            self.pid=runtime['pid'];self.previous.clear();self.graph.samples.clear()
        self.rows=runtime.get('applications',[])
        measured=rates['application'] or rates['ip'];down=measured['down'];up=measured['up']
        download=runtime.get('application',{}).get('downloaded_bytes',runtime['transport'].get('rx_payload_bytes',0)) if runtime.get('application') else runtime['transport'].get('rx_payload_bytes',0)
        upload=runtime.get('application',{}).get('uploaded_bytes',runtime['transport'].get('tx_payload_bytes',0)) if runtime.get('application') else runtime['transport'].get('tx_payload_bytes',0)
        if self.filter_paths:
            down=up=download=upload=0
            for row in self.rows:
                key=(row['pid'],row.get('created_filetime'),row.get('generation'));old=self.previous.get(key)
                if row['path'] in self.filter_paths:
                    download+=row['downloaded_bytes'];upload+=row['uploaded_bytes']
                    if old and now>old[0]:
                        down+=max(0,row['downloaded_bytes']-old[1])/(now-old[0]);up+=max(0,row['uploaded_bytes']-old[2])/(now-old[0])
                self.previous[key]=(now,row['downloaded_bytes'],row['uploaded_bytes'])
        self.graph.append(down,up)
        self.down.setText(f'↓  {human_bytes(download)}\n{human_bytes(down)}/s');self.up.setText(f'↑  {human_bytes(upload)}\n{human_bytes(up)}/s');self.total.setText(human_bytes(download+upload))
        paths=[p for p in runtime['transport'].get('paths',[]) if p.get('enabled',True)];healthy=sum(p['healthy'] for p in paths)
        encrypted=rates['encrypted'];self.extra.setText(f"VPS {runtime['peer'][0]} · {healthy}/{len(paths)} links\nEncrypted tunnel ↓ {human_bytes(encrypted['down'])}/s  ↑ {human_bytes(encrypted['up'])}/s")
        self.caption.setText(('Application payload · excludes duplicate copies and tunnel retransmissions' if rates['application'] else 'Tunnel IP throughput · includes inner headers and retransmissions')+
                             (' · application filter active' if self.filter_paths else ''))
        self._render_tables()

    def set_active(self,active):
        previous=getattr(self,'_active',True);self._active=bool(active)
        if self._active and not previous:self._render_tables()

    def _render_tables(self,*args):
        if not getattr(self,'_active',True) or self.views.currentIndex()!=1:return
        rows=[r for r in self.rows if not self.filter_paths or r['path'] in self.filter_paths]
        self.app_table.setRowCount(len(rows));hosts=[]
        for index,row in enumerate(sorted(rows,key=lambda r:r['uploaded_bytes']+r['downloaded_bytes'],reverse=True)):
            name=QTableWidgetItem(row.get('name') or Path(row['path']).name);name.setToolTip(row['path'])
            if row['path'] not in self.icons and len(self.icons)<512:self.icons[row['path']]=self.icon_provider.icon(QFileInfo(row['path']))
            if row['path'] in self.icons:name.setIcon(self.icons[row['path']])
            self.app_table.setItem(index,0,name);self.app_table.setItem(index,1,QTableWidgetItem(human_bytes(row['downloaded_bytes'])));self.app_table.setItem(index,2,QTableWidgetItem(human_bytes(row['uploaded_bytes'])))
            for destination in row.get('destinations',[]):hosts.append((destination,row.get('name','')))
        self.host_table.setRowCount(len(hosts))
        for index,(host,name) in enumerate(hosts):
            self.host_table.setItem(index,0,QTableWidgetItem(host));self.host_table.setItem(index,1,QTableWidgetItem(name))
        # Endpoint-only metadata cannot safely establish TLS/HTTP or geolocation.
        self.protocol_table.setRowCount(1)
        self.protocol_table.setItem(0,0,QTableWidgetItem('Routed connections'))
        self.protocol_table.setItem(0,1,QTableWidgetItem(str(sum(r.get('active_connections',0) for r in rows))))
