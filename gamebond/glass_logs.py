"""Persistent, searchable tunnel events in the recovered GlassWire log layout."""
from datetime import datetime,timedelta
import html
import json
from pathlib import Path
import secrets
import os
import math
import time

from PyQt5.QtCore import Qt,QFileInfo
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QComboBox,QLineEdit,
    QScrollArea,QFrame,QFileIconProvider)

from .glass_theme import GlassTheme,ROOT


class EventJournal:
    def __init__(self,path=None,limit=2048):
        self.path=Path(path or ROOT/'.runtime/dashboard-events.json');self.limit=limit;self.events=[];self.read_through=0;self.sequence=0;self.error=None
        try:
            if self.path.exists():
                if self.path.stat().st_size>4*1024*1024:raise ValueError('Event journal exceeds 4 MiB')
                saved=json.loads(self.path.read_text())
                if saved.get('version')!=1 or not isinstance(saved.get('events'),list):raise ValueError('Invalid event journal')
                self.events=saved['events'][-limit:];self.sequence=int(saved['sequence']);self.read_through=int(saved.get('read_through',0))
                for row in self.events:
                    if (not isinstance(row,dict) or not all(key in row for key in ('id','source','kind','text','timestamp'))
                            or type(row['id']) is not int or row['id']<1 or not isinstance(row['source'],str)
                            or not isinstance(row['text'],str) or type(row['timestamp']) not in (int,float)
                            or not math.isfinite(row['timestamp'])):raise ValueError('Invalid stored event')
        except (OSError,ValueError,KeyError,TypeError) as exc:self.error=str(exc);self.events=[]
        self.sources={r['source'] for r in self.events};self.state=None

    def append(self,source,kind,text,timestamp=None,application=None,destination=None):
        if source in self.sources:return False
        self.sequence+=1
        self.events.append(dict(id=self.sequence,source=source,kind=kind,text=text,timestamp=timestamp or time.time(),
                                application=application,destination=destination))
        self.events=self.events[-self.limit:];self.sources={r['source'] for r in self.events};self.save();return True

    def observe(self,runtime):
        changed=False
        if runtime:
            changed=self.ingest((runtime.get('app_events') or {}).get('events',[])) or changed
            state=(runtime['pid'],runtime['state'],tuple((p.get('interface_index'),p.get('healthy'),p.get('enabled',True)) for p in runtime.get('transport',{}).get('paths',[])))
            if self.state is not None and state!=self.state:
                paths=[p for p in runtime.get('transport',{}).get('paths',[]) if p.get('enabled',True)]
                healthy=sum(p.get('healthy',False) for p in paths)
                text=f"Tunnel {runtime['state']} · {healthy}/{len(paths)} enabled links · VPS {runtime['peer'][0]}"
                changed=self.append('state:'+secrets.token_hex(8),'connection_state',text) or changed
        else:
            state=None
            if self.state is not None:changed=self.append('state:'+secrets.token_hex(8),'connection_state','Tunnel disconnected') or changed
        self.state=state;return changed

    def ingest(self,events):
        changed=False
        for event in events:
            application=event.get('application',{})
            source=f"app:{event['id']}:{event['timestamp']}:{application.get('path','').casefold()}"
            changed=self.append(source,'new_app_tunnel_use',f"{application.get('name','Application')} used the tunnel for the first time",
                event['timestamp'],application,event.get('destination')) or changed
        return changed

    def save(self):
        if self.error:return  # Preserve a corrupt original for diagnosis.
        self.path.parent.mkdir(parents=True,exist_ok=True);temporary=self.path.with_name(self.path.name+'.'+secrets.token_hex(4)+'.tmp')
        try:
            payload=json.dumps(dict(version=1,sequence=self.sequence,read_through=self.read_through,events=self.events))
            while len(payload.encode())>4*1024*1024 and self.events:
                self.events.pop(0);payload=json.dumps(dict(version=1,sequence=self.sequence,read_through=self.read_through,events=self.events))
            from .atomic_io import replace_file
            temporary.write_text(payload);replace_file(temporary,self.path)
        except OSError as exc:self.error=str(exc)
        finally:
            if temporary.exists():temporary.unlink()


class LogPanel(QWidget):
    def __init__(self,parent=None,theme=None,journal=None):
        super().__init__(parent);self.theme=theme or GlassTheme();self.journal=journal or EventJournal();self.signature=None
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0);layout.setSpacing(0)
        toolbar=QWidget();toolbar.setStyleSheet(f'background:{self.theme.css("actionbar_bg")};');bar=QHBoxLayout(toolbar);bar.setContentsMargins(16,12,16,12)
        self.kind=QComboBox();self.kind.addItems(['Important','All events','New applications','Connection changes']);self.kind.currentIndexChanged.connect(self.refresh)
        self.period=QComboBox();self.period.addItems(['All Time','Today','Last Hour']);self.period.currentIndexChanged.connect(self.refresh)
        bar.addWidget(self.kind);bar.addWidget(self.period);bar.addStretch()
        read=QPushButton('Mark all as read');read.clicked.connect(self.mark_read);bar.addWidget(read)
        self.search=QLineEdit();self.search.setPlaceholderText('Search');self.search.setMaximumWidth(260);self.search.textChanged.connect(self.refresh);bar.addWidget(self.search);layout.addWidget(toolbar)
        self.scroll=QScrollArea();self.scroll.setWidgetResizable(True);self.scroll.setFrameShape(QFrame.NoFrame)
        self.content=QWidget();self.content.setStyleSheet(f'background:{self.theme.css("fw_top_area_bg")};');self.rows=QVBoxLayout(self.content);self.rows.setContentsMargins(38,18,38,30);self.rows.setSpacing(12)
        self.scroll.setWidget(self.content);layout.addWidget(self.scroll,1);self.icon_provider=QFileIconProvider()
        try:
            from .app_events import AppEventStore
            history=ROOT/'.runtime/app-history.json'
            if history.exists():self.journal.ingest(AppEventStore(history).snapshot(limit=256)['events'])
        except (OSError,ValueError,KeyError,TypeError):pass
        self.refresh()

    def update_runtime(self,runtime):
        if self.journal.observe(runtime):self.refresh()

    def mark_read(self):self.journal.read_through=self.journal.sequence;self.journal.save();self.refresh()

    def refresh(self,*args):
        while self.rows.count():
            item=self.rows.takeAt(0)
            if item.widget():item.widget().deleteLater()
        today=datetime.now().date();search=self.search.text().casefold();previous=None;count=0
        for event in reversed(self.journal.events):
            stamp=datetime.fromtimestamp(event['timestamp']);date=stamp.date()
            if self.period.currentIndex()==1 and date!=today:continue
            if self.period.currentIndex()==2 and event['timestamp']<time.time()-3600:continue
            kind=self.kind.currentIndex()
            if kind==2 and event['kind']!='new_app_tunnel_use':continue
            if kind==3 and event['kind']!='connection_state':continue
            if search and search not in (event['text']+' '+str(event.get('destination',''))+' '+str(event.get('application',''))).casefold():continue
            if date!=previous:
                label=QLabel('Today' if date==today else 'Yesterday' if date==today-timedelta(days=1) else date.strftime('%d %B %Y'))
                label.setStyleSheet('color:#5e6b74;font-size:12px;margin:8px 0;');self.rows.addWidget(label);previous=date
            card=QFrame();unread=event['id']>self.journal.read_through
            card.setStyleSheet(f'QFrame{{background:{"#fffaf0" if unread and not self.theme.dark else self.theme.css("gw_mainbg")};border:1px solid {self.theme.css("graph_bottomline")};border-radius:5px;}} QLabel{{border:0;background:transparent;}}')
            row=QHBoxLayout(card);row.setContentsMargins(18,18,22,18);row.setSpacing(14)
            badge=QLabel('NEW' if event['kind']=='new_app_tunnel_use' else '●');badge.setAlignment(Qt.AlignCenter);badge.setFixedSize(32,32)
            badge.setStyleSheet('background:#70bf24;color:white;border:0;border-radius:16px;font-size:9px;');row.addWidget(badge)
            application=event.get('application')
            if application and application.get('path'):
                icon=QLabel();icon.setPixmap(self.icon_provider.icon(QFileInfo(application['path'])).pixmap(17,17));row.addWidget(icon)
            body=QLabel(html.escape(event['text'])+((' to <b>'+html.escape(str(event['destination']))+'</b>') if event.get('destination') else ''))
            body.setWordWrap(True);body.setTextFormat(Qt.RichText);row.addWidget(body,1)
            details=QLabel(('First tunnel activity' if event['kind']=='new_app_tunnel_use' else 'Connection state')+'\n'+stamp.strftime('%I:%M %p').lstrip('0'))
            details.setAlignment(Qt.AlignRight|Qt.AlignVCenter);details.setStyleSheet('color:#969da6;font-size:11px;');row.addWidget(details)
            self.rows.addWidget(card);count+=1
            if count>=256:break
        if not count:
            empty=QLabel('No matching tunnel events');empty.setAlignment(Qt.AlignCenter);empty.setStyleSheet('color:#969da6;padding:70px;');self.rows.addWidget(empty)
        if self.journal.error:
            warning=QLabel('History could not be saved: '+self.journal.error);warning.setWordWrap(True);self.rows.addWidget(warning)
        self.rows.addStretch()
