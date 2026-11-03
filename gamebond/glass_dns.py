"""Simple DNS record management; saved configuration and live state stay distinct."""
import copy
import ipaddress
import re
from pathlib import Path

from PyQt5.QtCore import Qt,QSize,pyqtSignal
from PyQt5.QtGui import QPainter,QColor,QPen
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QCheckBox,QFormLayout,QSpinBox,
    QLineEdit,QPushButton,QTableWidget,QTableWidgetItem,QHeaderView,QComboBox,QAbstractItemView,
    QToolButton,QDialog,QDialogButtonBox)

from .widget_data import CONFIG
from .dns import normalize_name
from .dns_management import save_profile
from .atomic_io import read_json_shared


class DNSSwitch(QCheckBox):
    def sizeHint(self):return QSize(48+self.fontMetrics().horizontalAdvance(self.text()),28)
    def hitButton(self,point):return self.rect().contains(point)
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        if not self.isEnabled():painter.setOpacity(.5)
        top=(self.height()-20)//2;painter.setPen(Qt.NoPen);painter.setBrush(QColor('#3978e8' if self.isChecked() else '#b8c0cb'));painter.drawRoundedRect(0,top,36,20,10,10)
        painter.setBrush(QColor('white'));painter.drawEllipse(18 if self.isChecked() else 2,top+2,16,16)
        painter.setPen(self.palette().windowText().color());painter.drawText(self.rect().adjusted(46,0,0,0),Qt.AlignVCenter|Qt.AlignLeft,self.text())
        if self.hasFocus():painter.setPen(QPen(QColor('#3978e8'),1,Qt.DotLine));painter.setBrush(Qt.NoBrush);painter.drawRoundedRect(self.rect().adjusted(0,0,-1,-1),3,3)


class DNSRecordDialog(QDialog):
    def __init__(self,parent,on_save,record=None):
        super().__init__(parent);self.on_save=on_save;self.setWindowTitle('Edit DNS record' if record else 'Add DNS record');self.resize(470,260)
        layout=QVBoxLayout(self);form=QFormLayout();self.family=QComboBox();self.family.addItem('IPv4 address (A)','A');self.family.addItem('IPv6 address (AAAA)','AAAA')
        self.name=QLineEdit();self.name.setPlaceholderText('example.com');self.content=QLineEdit();self.content.setPlaceholderText('An IP address, such as 192.0.2.10')
        form.addRow('Type',self.family);form.addRow('Name',self.name);form.addRow('IP address',self.content);layout.addLayout(form)
        hint=QLabel('Use a full website name. For multiple IP addresses, separate them with commas.');hint.setWordWrap(True);layout.addWidget(hint)
        self.error=QLabel();self.error.setWordWrap(True);self.error.setStyleSheet('color:#b04733;');layout.addWidget(self.error)
        buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel);buttons.accepted.connect(self.submit);buttons.rejected.connect(self.reject);layout.addWidget(buttons)
        if record:
            name,family,content=record;self.name.setText(name);self.family.setCurrentIndex(self.family.findData(family));self.content.setText(content)

    def submit(self):
        try:
            from .windows_dns import _hostname
            name=normalize_name(self.name.text().strip());_hostname(name);family=self.family.currentData()
            addresses=[str(ipaddress.ip_address(v)) for v in re.split(r'[,;\s]+',self.content.text().strip()) if v]
            if not 1<=len(addresses)<=16:raise ValueError('Enter between 1 and 16 IP addresses.')
            if any(ipaddress.ip_address(v).version!=(4 if family=='A' else 6) for v in addresses):raise ValueError('Choose the record type that matches your IP address.')
            error=self.on_save((name,family,', '.join(addresses)))
            if error:self.error.setText(error);return
        except ValueError as exc:self.error.setText(str(exc));return
        self.accept()


class DNSPanel(QWidget):
    settingsChanged=pyqtSignal(dict)

    def __init__(self,parent=None,*,config_path=None):
        super().__init__(parent);self.setObjectName('dnsManagementPanel');self.path=Path(config_path or CONFIG)
        self.runtime=None;self.config={};self.baseline=None;self.dirty=False;self.loading=False;self.dialogs=[]
        layout=QVBoxLayout(self);layout.setContentsMargins(20,16,20,14);layout.setSpacing(12)
        row=QHBoxLayout();title=QLabel('DNS records');title.setStyleSheet('font-size:22px;font-weight:600;');row.addWidget(title);row.addStretch()
        self.status=QLabel();self.status.setObjectName('dnsRuntimeStatus');row.addWidget(self.status);layout.addLayout(row)
        row=QHBoxLayout();self.enabled=DNSSwitch('Custom DNS');self.enabled.setObjectName('dnsProfileEnabled');self.enabled.setStyleSheet('font-weight:600;')
        self.enabled_state=QLabel();row.addWidget(self.enabled);row.addWidget(self.enabled_state);row.addStretch();layout.addLayout(row)
        self.notice=QLabel();self.notice.setWordWrap(True);layout.addWidget(self.notice)
        row=QHBoxLayout();self.search=QLineEdit();self.search.setPlaceholderText('Search DNS records');row.addWidget(self.search,1)
        self.add_button=QPushButton('Add record');self.add_button.setStyleSheet('background:#3978e8;color:white;padding:7px 18px;border-radius:5px;');row.addWidget(self.add_button);layout.addLayout(row)
        self.records=QTableWidget(0,4);self.records.setObjectName('dnsOverridesTable');self.records.setHorizontalHeaderLabels(['Type','Name','Content','Actions'])
        self.records.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeToContents);self.records.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch);self.records.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch);self.records.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeToContents)
        self.records.verticalHeader().hide();self.records.setShowGrid(False);self.records.setAlternatingRowColors(True);self.records.setSelectionBehavior(QAbstractItemView.SelectRows);self.records.setEditTriggers(QAbstractItemView.NoEditTriggers);layout.addWidget(self.records,1)
        row=QHBoxLayout();self.count=QLabel();row.addWidget(self.count);row.addStretch();self.advanced_button=QToolButton();self.advanced_button.setText('Advanced settings');self.advanced_button.setCheckable(True);self.advanced_button.setArrowType(Qt.RightArrow);self.advanced_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon);row.addWidget(self.advanced_button);layout.addLayout(row)
        self.advanced=QWidget();advanced=QVBoxLayout(self.advanced);advanced.setContentsMargins(0,0,0,0);fields=QFormLayout()
        self.listener=QLabel();fields.addRow('Local resolver',self.listener);self.ttl=QSpinBox();self.ttl.setRange(0,300);self.ttl.setSuffix(' seconds');self.ttl.setSpecialValueText('No caching');fields.addRow('Record TTL',self.ttl)
        upstream=QHBoxLayout();self.forward=QCheckBox('Forward other names');self.upstream=QLineEdit();self.upstream.setPlaceholderText('Public IPv4 resolver');self.port=QSpinBox();self.port.setRange(1,65535);self.port.setValue(53)
        upstream.addWidget(self.forward);upstream.addWidget(self.upstream,1);upstream.addWidget(self.port);fields.addRow('Upstream resolver',upstream);advanced.addLayout(fields)
        self.metrics=QLabel();advanced.addWidget(self.metrics);details=QLabel('This is a saved DNS override profile. The current userspace tunnel does not activate the managed DNS responder. Saving does not change Windows DNS, hosts files, or the running tunnel.');details.setWordWrap(True);advanced.addWidget(details)
        layout.addWidget(self.advanced);self.advanced.hide()
        row=QHBoxLayout();self.feedback=QLabel();self.feedback.setWordWrap(True);row.addWidget(self.feedback,1);self.reload_button=QPushButton('Reload saved');self.save_button=QPushButton('Save changes');row.addWidget(self.reload_button);row.addWidget(self.save_button);layout.addLayout(row)
        self.enabled.toggled.connect(self._toggle);self.forward.toggled.connect(self._forward_changed);self.ttl.valueChanged.connect(self._changed);self.port.valueChanged.connect(self._changed);self.upstream.textChanged.connect(self._changed)
        self.search.textChanged.connect(self.filter_records);self.add_button.clicked.connect(lambda:self.edit_record());self.records.cellDoubleClicked.connect(lambda row,column:self.edit_record(row));self.reload_button.clicked.connect(self.reload);self.save_button.clicked.connect(self.save);self.advanced_button.toggled.connect(self._show_advanced)
        self.reload()

    def _show_advanced(self,value):self.advanced.setVisible(value);self.advanced_button.setArrowType(Qt.DownArrow if value else Qt.RightArrow)

    def _changed(self,*args):
        if not self.loading:self.dirty=True;self.save_button.setEnabled(True)

    def _forward_changed(self,value):self.upstream.setEnabled(value);self.port.setEnabled(value);self._changed()

    def _toggle(self,value):
        self.enabled_state.setText('On (saved setting)' if value else 'Off')
        if self.loading:return
        dns=copy.deepcopy(self.baseline) or dict(bind=[self.config.get('client_tunnel_ip','10.77.0.2'),53],records={},ttl=15,upstream=None)
        dns['enabled']=value
        try:config=save_profile(self.path,dns,expected=self.baseline)
        except (OSError,ValueError,TypeError,KeyError,RuntimeError) as exc:
            self.loading=True;self.enabled.setChecked(not value);self.loading=False
            self.feedback.setText('Add a DNS record before turning Custom DNS on.' if value and not dns['records'] else str(exc));return
        self.config=copy.deepcopy(config);self.baseline=copy.deepcopy(config['dns']);self.feedback.setText('Custom DNS setting saved.');self.settingsChanged.emit(config);self.update_runtime(self.runtime)

    def _row(self,row):return self.records.item(row,1).text(),self.records.item(row,0).text(),self.records.item(row,2).text()

    def add_record(self,hostname='',family='A',addresses=''):
        row=self.records.rowCount();self.records.insertRow(row)
        for column,text in enumerate((family,hostname,addresses)):self.records.setItem(row,column,QTableWidgetItem(text))
        actions=QWidget();buttons=QHBoxLayout(actions);buttons.setContentsMargins(2,0,2,0);buttons.setSpacing(3)
        name_item=self.records.item(row,1)
        edit=QPushButton('Edit');remove=QPushButton('Delete');edit.clicked.connect(lambda:self.edit_record(self.records.row(name_item)));remove.clicked.connect(lambda:self.delete_record(self.records.row(name_item)))
        buttons.addWidget(edit);buttons.addWidget(remove);self.records.setCellWidget(row,3,actions);self.records.setRowHeight(row,38);self._changed();self.filter_records()

    def edit_record(self,row=None):
        if row is not None and row<0:return
        dialog=DNSRecordDialog(self,lambda record:self._commit_record(row,record),self._row(row) if row is not None else None)
        self.dialogs.append(dialog);dialog.finished.connect(lambda _:self.dialogs.remove(dialog) if dialog in self.dialogs else None);dialog.setAttribute(Qt.WA_DeleteOnClose);dialog.open()

    def _commit_record(self,row,record):
        name,family,content=record
        for other in range(self.records.rowCount()):
            host,kind,_=self._row(other)
            if other!=row and normalize_name(host)==name and kind==family:return 'This record already exists. Edit its IP addresses instead.'
        before=[self._row(i) for i in range(self.records.rowCount())];was_dirty=self.dirty
        if row is None:self.add_record(name,family,content)
        else:
            for column,text in enumerate((family,name,content)):self.records.item(row,column).setText(text)
            self._changed()
        if self.save():return None
        error=self.feedback.text();self._restore_rows(before);self.dirty=was_dirty;self.save_button.setEnabled(was_dirty);return error

    def _restore_rows(self,rows):
        loading=self.loading;self.loading=True;self.records.setRowCount(0)
        for name,family,content in rows:self.add_record(name,family,content)
        self.loading=loading

    def delete_record(self,row):
        if row<0:return
        before=[self._row(i) for i in range(self.records.rowCount())];self.records.removeRow(row);self._changed()
        if not self.records.rowCount():self.loading=True;self.enabled.setChecked(False);self.loading=False
        if not self.save():self._restore_rows(before);self.loading=True;self.enabled.setChecked(bool((self.baseline or {}).get('enabled')));self.loading=False
        self.filter_records()

    def filter_records(self,*args):
        search=self.search.text().strip().casefold();visible=0
        for row in range(self.records.rowCount()):
            match=not search or any(search in self.records.item(row,c).text().casefold() for c in range(3));self.records.setRowHidden(row,not match);visible+=int(match)
        total=self.records.rowCount();self.count.setText(f'{visible} of {total} records' if search else f'{total} DNS record'+('' if total==1 else 's'))

    def reload(self):
        try:self.update_config(read_json_shared(self.path),force=True)
        except (OSError,ValueError,TypeError) as exc:self.feedback.setText('Could not read DNS settings: '+str(exc));self.save_button.setEnabled(False)

    def update_config(self,config,*,force=False):
        if self.dirty and not force:return
        self.config=copy.deepcopy(config);self.baseline=copy.deepcopy(config.get('dns'));dns=self.baseline or {};self.loading=True
        try:
            self.enabled.setChecked(dns.get('enabled',False));self.enabled_state.setText('On (saved setting)' if self.enabled.isChecked() else 'Off');self.ttl.setValue(dns.get('ttl',15));self.listener.setText(f"{config.get('client_tunnel_ip','10.77.0.2')}:53")
            upstream=dns.get('upstream');self.forward.setChecked(bool(upstream));self.upstream.setText(upstream[0] if upstream else '');self.port.setValue(upstream[1] if upstream else 53);self.upstream.setEnabled(bool(upstream));self.port.setEnabled(bool(upstream))
            self._restore_rows([(host,family,', '.join(addresses)) for host,types in dns.get('records',{}).items() for family,addresses in types.items()])
        finally:self.loading=False
        self.dirty=False;self.save_button.setEnabled(False);self.filter_records();self.update_runtime(self.runtime)

    def profile(self):
        dns=copy.deepcopy(self.baseline) or {};records={}
        for row in range(self.records.rowCount()):
            name,family,content=self._row(row);name=normalize_name(name.strip());addresses=[v for v in re.split(r'[,;\s]+',content.strip()) if v]
            if family in records.get(name,{}):raise ValueError(f'{name} already has a {family} row; combine its addresses')
            records.setdefault(name,{})[family]=addresses
        dns.update(enabled=self.enabled.isChecked(),bind=[self.config['client_tunnel_ip'],53],records=records,ttl=self.ttl.value(),upstream=[self.upstream.text().strip(),self.port.value()] if self.forward.isChecked() else None);return dns

    def save(self):
        try:config=save_profile(self.path,self.profile(),expected=self.baseline)
        except (OSError,ValueError,TypeError,KeyError,RuntimeError) as exc:self.feedback.setText(str(exc));return False
        self.update_config(config,force=True);self.feedback.setText('DNS settings saved.');self.settingsChanged.emit(config);return True

    def update_runtime(self,runtime):
        self.runtime=runtime;stats=(runtime or {}).get('dns')
        if isinstance(stats,dict):
            self.status.setText('Active on this connection');self.notice.setText('Your custom DNS responder is running.');self.metrics.setText(' · '.join(f'{title}: {stats.get(key,0)}' for key,title in [('queries','Queries'),('overrides','Overrides'),('forwarded','Forwarded'),('upstream_errors','Errors')]))
            if not self.enabled.isChecked():self.notice.setText('The saved setting is off. DNS is still running on the current connection until it is restarted.')
        else:
            self.status.setText('Not active on this connection' if runtime else 'Not active')
            self.notice.setText('Custom DNS is not supported by this connection yet. You can still manage your saved records here.');self.metrics.setText('No live DNS counters')

    def shutdown(self):
        for dialog in list(self.dialogs):dialog.reject()
