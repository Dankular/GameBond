"""GlassWire-style Protect view for actual authenticated GameBond applications."""
from collections import OrderedDict, deque
import json
import ntpath
import time

from PyQt5.QtCore import Qt,QFileInfo,pyqtSignal,QSignalBlocker,QPointF,QRectF
from PyQt5.QtGui import QPainter,QPainterPath,QPen,QColor,QFont,QIcon
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QComboBox,QLineEdit,
    QTableWidget,QTableWidgetItem,QHeaderView,QAbstractItemView,QFileIconProvider,QFileDialog,QMenu,QMessageBox)

from .app_policy import CONFIG,PolicyEvaluator,canonical_path,normalize_rule,save_policy_settings
from .glass_theme import GlassTheme

PROFILE_NAMES={'automatic':'Automatic','gaming':'Gaming','streaming':'Streaming','call':'Call','bulk':'Bulk'}


def _speed(value):
    if value is None:return '—'
    for unit in ('B/s','KB/s','MB/s','GB/s'):
        if value<1000 or unit=='GB/s':return f'{value:.0f} {unit}' if value>=100 or unit=='B/s' else f'{value:.1f} {unit}'
        value/=1000


class ProtectionSwitch(QPushButton):
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        active=self.isChecked();color=QColor('#6ad68c' if active else '#8fa4c1')
        painter.setPen(Qt.NoPen);painter.setBrush(color)
        painter.drawRoundedRect(QRectF(0,0,self.width(),self.height()),self.height()/2,self.height()/2)
        knob=QRectF(self.width()/2 if active else 1,1,self.width()/2-1,self.height()-2)
        painter.setBrush(QColor('white'));painter.drawRoundedRect(knob,knob.height()/2,knob.height()/2)
        painter.setPen(color);font=QFont(self.font());font.setPixelSize(9);font.setWeight(QFont.Medium);painter.setFont(font)
        painter.drawText(knob,Qt.AlignCenter,'ON' if active else 'OFF')


class PillCombo(QComboBox):
    def __init__(self,theme,parent=None,colors=None,radius=14):
        super().__init__(parent);self.theme=theme;self.colors=colors;self.radius=radius
        self.setMinimumHeight(28)
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        foreground,background=self.colors or (self.theme.color('actionbar_btn_txt','n'),self.theme.color('actionbar_btn_bg','n'))
        foreground,background=QColor(foreground),QColor(background)
        painter.setPen(QPen(self.theme.color('actionbar_btn_stroke','n'),1) if not self.colors else Qt.NoPen)
        painter.setBrush(background);painter.drawRoundedRect(QRectF(.5,.5,self.width()-1,self.height()-1),self.radius,self.radius)
        painter.setPen(foreground);painter.setFont(self.font())
        painter.drawText(QRectF(11,0,self.width()-34,self.height()),Qt.AlignVCenter|Qt.AlignLeft,self.currentText())
        arrow=QPainterPath(QPointF(self.width()-20,self.height()/2-2));arrow.lineTo(self.width()-16,self.height()/2+2);arrow.lineTo(self.width()-12,self.height()/2-2)
        painter.setPen(QPen(foreground,1));painter.drawPath(arrow)


class TrafficSparkline(QWidget):
    def __init__(self,samples,theme,parent=None):
        super().__init__(parent);self.samples=list(samples);self.theme=theme;self.setMinimumWidth(110)
    def paintEvent(self,event):
        if len(self.samples)<2:return
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        width,height=max(1,self.width()-8),max(1,self.height()-6)
        ceiling=max(1,max(max(down,up) for down,up in self.samples))
        for index,color in ((0,'#ffd642'),(1,'#fa8d73')):
            path=QPainterPath(QPointF(4,height+2))
            for i,sample in enumerate(self.samples):path.lineTo(4+i*width/(len(self.samples)-1),height+2-sample[index]/ceiling*height)
            path.lineTo(width+4,height+2);path.closeSubpath()
            painter.fillPath(path,QColor(color))


class ProtectPanel(QWidget):
    settingsChanged=pyqtSignal(dict)
    changed=pyqtSignal(dict)

    def __init__(self,parent=None,theme=None):
        super().__init__(parent);self.theme=theme or GlassTheme();self.runtime=None
        self.rows={};self.baselines={};self.histories={};self.current_path=None;self.rendering=False
        self.icons=OrderedDict();self.icon_provider=QFileIconProvider();self._load_config()
        self.setStyleSheet(self.theme.stylesheet())
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0);layout.setSpacing(0)
        toolbar=QWidget();toolbar.setObjectName('protectToolbar');toolbar.setMinimumHeight(110)
        toolbar.setStyleSheet(f'QWidget#protectToolbar{{background:{self.theme.css("fw_top_area_bg")};border-bottom:1px solid #d7d9dd;}}')
        top=QHBoxLayout(toolbar);top.setContentsMargins(35,16,35,16);top.setSpacing(30)
        self.enable=ProtectionSwitch();self.enable.setCheckable(True);self.enable.setFixedSize(66,25)
        self.enable.setChecked(self.evaluator.enabled);self.enable.clicked.connect(self._toggle)
        self._switch_style()
        self._section(top,'Tunnel protection',self.enable)
        self.profile=PillCombo(self.theme);self.profile.setMinimumWidth(190)
        for key,name in PROFILE_NAMES.items():self.profile.addItem(name,key)
        self.profile.currentIndexChanged.connect(self._profile_changed)
        self._section(top,'Traffic profile',self.profile)
        self.mode=PillCombo(self.theme);self.mode.addItems(['Click to block','Show configured rules']);self.mode.currentIndexChanged.connect(self._render)
        self.mode.setMinimumWidth(190);self._section(top,'Protection mode',self.mode)
        self.search=QLineEdit();self.search.setPlaceholderText('Search');self.search.setMinimumWidth(220)
        self.search.textChanged.connect(self._render);self._section(top,'Search',self.search,stretch=1)
        self.add=QPushButton('Add app…');self.add.clicked.connect(self._add_app);top.addWidget(self.add,0,Qt.AlignBottom)
        layout.addWidget(toolbar)
        self.table=QTableWidget(0,8);self.table.setHorizontalHeaderLabels(['Apps','In Connections','Out Connections','Version','Hosts','↓','↑','Traffic'])
        self.table.setAlternatingRowColors(True);self.table.setShowGrid(False);self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(30);self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection);self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(False);self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu);self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.cellDoubleClicked.connect(self._details)
        widths=(260,108,108,80,200,78,78,190)
        for index,width in enumerate(widths):self.table.setColumnWidth(index,width)
        self.table.horizontalHeader().setStretchLastSection(True);layout.addWidget(self.table,1)
        self.feedback=QLabel('Protect applies to new outbound tunnel connections. It does not change the Windows firewall.')
        self.feedback.setWordWrap(True);self.feedback.setContentsMargins(20,9,20,9)
        self.feedback.setStyleSheet(f'color:{self.theme.css("on_srf_s2")};font-size:11px;border-top:1px solid #e1e3e7;')
        layout.addWidget(self.feedback);self._render();self._select_profile()

    def _load_config(self):
        self.config=json.loads(CONFIG.read_text(encoding='utf-8'));self.evaluator=PolicyEvaluator(self.config)

    def _section(self,layout,title,widget,stretch=0):
        container=QVBoxLayout();container.setSpacing(10)
        label=QLabel(title);label.setStyleSheet(f'color:{self.theme.css("on_srf_s2")};font-size:12px;')
        container.addWidget(label);container.addWidget(widget);layout.addLayout(container,stretch)

    def _switch_style(self):
        active=self.enable.isChecked();self.enable.setText('ON' if active else 'OFF')
        self.enable.update()

    def _persist(self,**kwargs):
        try:self.config=save_policy_settings(**kwargs);self.evaluator=PolicyEvaluator(self.config)
        except (ValueError,TypeError,OSError,RuntimeError) as exc:
            self.feedback.setText('Could not save policy: '+str(exc));return False
        self.feedback.setText('Saved. New outbound connections read updated rules. Reconnect to re-evaluate existing connections.' if self.runtime else
                              'Saved. Rules apply when the tunnel starts.')
        self.settingsChanged.emit(self.config);self.changed.emit(self.config);self._render();return True

    def _toggle(self):
        requested=self.enable.isChecked()
        if not self._persist(enabled=requested):
            self.enable.setChecked(self.evaluator.enabled)
        self._switch_style()

    def _rule(self,path):
        return dict(self.evaluator.rules.get(path,dict(outbound='allow',profile=self.evaluator.default_profile)))

    def _set_outbound(self,path,value):
        if self.rendering:return
        rule=self._rule(path);rule['outbound']=value
        self._persist(updates={path:rule})

    def _profile_changed(self):
        if self.rendering:return
        value=self.profile.currentData()
        if self.current_path:
            rule=self._rule(self.current_path);rule['profile']=value;self._persist(updates={self.current_path:rule})
        else:self._persist(default_profile=value)

    def _select_profile(self):
        value=self._rule(self.current_path)['profile'] if self.current_path else self.evaluator.default_profile
        with QSignalBlocker(self.profile):self.profile.setCurrentIndex(self.profile.findData(value))
        self.profile.setToolTip('Selected application profile' if self.current_path else 'Default profile for applications without an explicit rule')

    def _selection_changed(self):
        if self.rendering:return
        selected=self.table.selectionModel().selectedRows()
        self.current_path=self.table.item(selected[0].row(),0).data(Qt.UserRole) if selected else None
        self._select_profile()

    def _add_app(self):
        path,_=QFileDialog.getOpenFileName(self,'Choose application','','Applications (*.exe)')
        if path:self._persist(updates={path:dict(outbound='allow',profile='automatic')})

    def _icon(self,path):
        icon=self.icons.get(path)
        if icon is None:
            icon=self.icon_provider.icon(QFileInfo(path));self.icons[path]=icon
            while len(self.icons)>512:self.icons.popitem(last=False)
        return icon

    def update_runtime(self,runtime):
        self.runtime=runtime;now=time.monotonic();merged={};seen=set()
        rows=(runtime or {}).get('applications',[])
        if not isinstance(rows,list):rows=[]
        for source in rows[:512]:
            if not isinstance(source,dict):continue
            try:key=canonical_path(source.get('path'))
            except ValueError:continue
            counts=(source.get('downloaded_bytes'),source.get('uploaded_bytes'))
            if any(type(n) is not int or n<0 for n in counts):continue
            identity=(source.get('pid'),source.get('created_filetime'),source.get('generation'))
            previous=self.baselines.get(identity);seen.add(identity)
            rates=(0.,0.)
            if previous and now>previous[0] and all(value>=old for value,old in zip(counts,previous[1:])):
                rates=tuple((value-old)/(now-previous[0]) for value,old in zip(counts,previous[1:]))
            self.baselines[identity]=(now,*counts)
            row=merged.setdefault(key,dict(path=source['path'],name=source.get('name') or ntpath.basename(key),
                down=0.,up=0.,uploaded_bytes=0,downloaded_bytes=0,active_connections=0,destinations=[],verified=True,pids=[],
                version=source.get('version') if isinstance(source.get('version'),str) else '—'))
            row['down']+=rates[0];row['up']+=rates[1];row['downloaded_bytes']+=counts[0];row['uploaded_bytes']+=counts[1]
            row['active_connections']+=max(0,source.get('active_connections',0));row['pids'].append(source.get('pid'))
            destinations=source.get('destinations',[])
            if isinstance(destinations,list):row['destinations']=list(dict.fromkeys(row['destinations']+[str(v) for v in destinations[:8]]))[:16]
        self.baselines={key:value for key,value in self.baselines.items() if key in seen}
        for key,row in merged.items():
            history=self.histories.setdefault(key,deque(maxlen=60));history.append((row['down'],row['up']))
        self.histories={key:value for key,value in self.histories.items() if key in merged}
        self.rows=merged;self._render()
        attribution=(runtime or {}).get('app_attribution',{})
        applied=(runtime or {}).get('application_policy')
        if runtime and not attribution.get('available',False):
            self.feedback.setText('Application attribution is unavailable in this session. Restart the client to use authenticated per-app protection.')
        elif applied and self._applied_matches(applied):
            self.feedback.setText('Current rules apply to new outbound tunnel connections. Existing connections retain their original policy; unsolicited inbound services are not exposed.')
        elif applied:
            self.feedback.setText('Saved changes will be read for the next new outbound connection. Reconnect to re-evaluate existing connections.')
        elif runtime:
            self.feedback.setText('Per-app enforcement is unavailable in this running session. Restart the client to enable it.')

    def _applied_matches(self,applied):
        if isinstance(applied,dict) and isinstance(applied.get('policy_digest'),str):
            return applied['policy_digest']==self.evaluator.digest()
        try:
            return PolicyEvaluator(dict(protection_enabled=applied['enabled'],default_app_profile=applied['default_profile'],
                                        app_rules=applied['rules'])).snapshot()==self.evaluator.snapshot()
        except (ValueError,TypeError,KeyError):return False

    def set_active(self,active):
        previous=getattr(self,'_active',True);self._active=bool(active)
        if self._active and not previous:self._render()

    def _render(self):
        if not hasattr(self,'table') or not getattr(self,'_active',True):return
        self.rendering=True;self.table.setUpdatesEnabled(False)
        try:
            entries=dict(self.rows)
            for path in self.evaluator.rules:
                entries.setdefault(path,dict(path=path,name=ntpath.basename(path),verified=False,destinations=[],active_connections=0))
            query=self.search.text().strip().casefold()
            entries=[(key,row) for key,row in entries.items() if (not query or query in key.casefold() or
                     query in row['name'].casefold() or any(query in v.casefold() for v in row['destinations']))
                     and (self.mode.currentIndex()!=1 or key in self.evaluator.rules)]
            entries.sort(key=lambda pair:(not bool(pair[1].get('active_connections')),not pair[1]['verified'],pair[1]['name'].casefold()))
            if self.current_path is not None and self.current_path not in {key for key,_ in entries}:
                self.current_path=None;self._select_profile()
            paths=tuple(path for path,_ in entries[:512])
            rebuild=paths!=getattr(self,'_row_paths',None)
            if rebuild:
                self.table.clearContents();self.table.setRowCount(len(paths));self._row_paths=paths
            for index,(path,row) in enumerate(entries[:512]):
                rule=self._rule(path)
                if rebuild:
                    name=QTableWidgetItem(self._icon(row['path']),row['name']);name.setData(Qt.UserRole,path)
                    self.table.setItem(index,0,name)
                    inbound=QLabel('Not exposed');inbound.setAlignment(Qt.AlignCenter)
                    inbound.setToolTip('This tunnel accepts replies to outbound flows; it does not expose inbound listening services.')
                    inbound.setStyleSheet('color:#9da4af;background:transparent;font-size:11px;');self.table.setCellWidget(index,1,inbound)
                    outbound=PillCombo(self.theme,radius=4);outbound.addItem('Allowed','allow');outbound.addItem('Blocked','block')
                    outbound.setContentsMargins(9,4,9,4)
                    outbound.currentIndexChanged.connect(lambda _,key=path,editor=outbound:self._set_outbound(key,editor.currentData()))
                    self.table.setCellWidget(index,2,outbound)
                    for column in range(3,7):
                        cell=QTableWidgetItem()
                        if column in (5,6):cell.setTextAlignment(Qt.AlignRight|Qt.AlignVCenter)
                        self.table.setItem(index,column,cell)
                    self.table.setCellWidget(index,7,TrafficSparkline([],self.theme))
                name=self.table.item(index,0)
                if name.text()!=row['name']:name.setText(row['name'])
                tooltip=row['path']+('\nVerified routed application' if row['verified'] else '\nConfigured rule; no verified tunnel usage in this session')
                if name.toolTip()!=tooltip:name.setToolTip(tooltip)
                outbound=self.table.cellWidget(index,2)
                colors=('#58a76c','#e4f2e7') if rule['outbound']=='allow' else ('#cf6d65','#f9e6e4')
                if outbound.colors!=colors:outbound.colors=colors;outbound.update()
                desired=outbound.findData(rule['outbound'])
                if outbound.currentIndex()!=desired:
                    with QSignalBlocker(outbound):outbound.setCurrentIndex(desired)
                hosts=row['destinations']
                values=(row.get('version','—'),hosts[0]+(f"  +{len(hosts)-1} more" if len(hosts)>1 else '') if hosts else '',
                        _speed(row.get('down')),_speed(row.get('up')))
                for column,value in enumerate(values,3):
                    cell=self.table.item(index,column)
                    if cell.text()!=value:cell.setText(value)
                sparkline=self.table.cellWidget(index,7);sparkline.samples=list(self.histories.get(path,[]));sparkline.update()
                if rebuild and path==self.current_path:self.table.selectRow(index)
            self.table.setToolTip('Showing the first 512 matching applications' if len(entries)>512 else '')
        finally:
            self.table.setUpdatesEnabled(True);self.rendering=False

    def _context_menu(self,position):
        row=self.table.rowAt(position.y())
        if row<0:return
        path=self.table.item(row,0).data(Qt.UserRole);menu=QMenu(self)
        menu.addAction('Allow outbound tunnel connections',lambda:self._set_outbound(path,'allow'))
        menu.addAction('Block outbound tunnel connections',lambda:self._set_outbound(path,'block'))
        profiles=menu.addMenu('Traffic profile')
        for key,name in PROFILE_NAMES.items():
            action=profiles.addAction(name);action.triggered.connect(lambda _,key=key,path=path:self._set_profile(path,key))
        if path in self.evaluator.rules:menu.addAction('Remove explicit rule',lambda:self._persist(remove_paths=[path]))
        menu.exec_(self.table.viewport().mapToGlobal(position))

    def _set_profile(self,path,profile):
        rule=self._rule(path);rule['profile']=profile;self._persist(updates={path:rule})

    def _details(self,row,column):
        path=self.table.item(row,0).data(Qt.UserRole);source=self.rows.get(path)
        text=path
        if source:text+='\n\nVerified tunnel activity\n'+str(source.get('active_connections',0))+' active connections\n'+'\n'.join(source['destinations'])
        else:text+='\n\nConfigured rule. No verified tunnel usage in this session.'
        QMessageBox.information(self,'Application tunnel details',text)
