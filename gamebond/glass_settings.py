"""Qt settings dialogs backed by the existing validated configuration writers."""
import json

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (QDialog,QVBoxLayout,QHBoxLayout,QLabel,QRadioButton,QButtonGroup,QListWidget,
    QPushButton,QFileDialog,QDialogButtonBox,QCheckBox,QMessageBox,QScrollArea,QWidget,QFormLayout,QComboBox,QDoubleSpinBox,QSpinBox,QGroupBox)

from .widget_data import CONFIG,save_applications,save_selection,save_link_policies,human_bytes,discover_links
from .capture import normalize_apps
from .link_policy import LinkPolicy,UsageLedger
from .glass_theme import ROOT


class SettingsDialog(QDialog):
    saved=pyqtSignal(dict)
    def __init__(self,title,parent=None):
        super().__init__(parent);self.setWindowTitle('GameBond · '+title);self.resize(620,480)
        self.config=json.loads(CONFIG.read_text());self.layout=QVBoxLayout(self)
        heading=QLabel(title);heading.setStyleSheet('font-size:20px;font-weight:500;padding:8px;');self.layout.addWidget(heading)
        self.body=QVBoxLayout();self.layout.addLayout(self.body,1)
        self.feedback=QLabel('Save and reconnect to apply.');self.feedback.setWordWrap(True);self.layout.addWidget(self.feedback)
        buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel);buttons.accepted.connect(self.save);buttons.rejected.connect(self.reject)
        self.layout.addWidget(buttons)
        self.buttons=buttons

    def save(self):
        try:config=self.write_config()
        except (ValueError,TypeError,OSError,RuntimeError) as exc:self.feedback.setText(str(exc));return
        self.saved.emit(config);self.accept()


class ApplicationsDialog(SettingsDialog):
    def __init__(self,parent=None):
        super().__init__('Application routing',parent)
        self.modes=QButtonGroup(self);self.all_apps=QRadioButton('All apps (default)');self.selected=QRadioButton('Selected apps only')
        self.modes.addButton(self.all_apps);self.modes.addButton(self.selected)
        self.all_apps.setChecked(self.config.get('capture_mode','all')=='all');self.selected.setChecked(not self.all_apps.isChecked())
        self.body.addWidget(self.all_apps);self.body.addWidget(self.selected)
        self.body.addWidget(QLabel('Application list for Selected apps mode'))
        self.list=QListWidget();self.list.setSelectionMode(QListWidget.ExtendedSelection)
        self.list.addItems(self.config.get('cod_executables',[]));self.body.addWidget(self.list,1)
        row=QHBoxLayout();add=QPushButton('Add apps…');remove=QPushButton('Remove selected')
        add.clicked.connect(self.add);remove.clicked.connect(self.remove);row.addWidget(add);row.addWidget(remove);row.addStretch();self.body.addLayout(row)
        self.feedback.setText('IPv4 capture. GameBond’s carrier and helpers are excluded automatically. Save and reconnect to apply.')

    def add(self):
        paths,_=QFileDialog.getOpenFileNames(self,'Choose applications','','Applications (*.exe)')
        try:apps=normalize_apps([self.list.item(i).text() for i in range(self.list.count())]+paths)
        except ValueError as exc:self.feedback.setText(str(exc));return
        self.list.clear();self.list.addItems(apps)

    def remove(self):
        for item in self.list.selectedItems():self.list.takeItem(self.list.row(item))

    def write_config(self):
        return save_applications('all' if self.all_apps.isChecked() else 'selected',[self.list.item(i).text() for i in range(self.list.count())])


class NetworksDialog(SettingsDialog):
    def __init__(self,links,parent=None):
        super().__init__('Select networks',parent);self.links=[];self.choices=[]
        note=QLabel('Choose two adapters. Offline adapters can stay selected; their addresses are discovered automatically when they return.');note.setWordWrap(True);self.body.addWidget(note)
        row=QHBoxLayout();self.selection_status=QLabel();self.refresh_button=QPushButton('Refresh adapters');self.refresh_button.clicked.connect(self.refresh)
        row.addWidget(self.selection_status,1);row.addWidget(self.refresh_button);self.body.addLayout(row)
        scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setFrameShape(QScrollArea.NoFrame)
        self.content=QWidget();self.list_layout=QVBoxLayout(self.content);self.list_layout.setAlignment(Qt.AlignTop);scroll.setWidget(self.content);self.body.addWidget(scroll,1)
        from .glass_panels import _AsyncCall
        self.worker=_AsyncCall(self);self.worker.done.connect(self._refreshed);self.worker.failed.connect(self._refresh_failed);self.finished.connect(lambda _:self.worker.shutdown())
        self._set_links(links)
        self.feedback.setText('Changes apply on your next connection. Saving does not start the tunnel.')
        if not links:self.refresh()

    def _selected_keys(self):
        return {choice.property('adapterIdentity') for _,choice in self.choices if choice.isChecked()}

    def _set_links(self,links):
        ids=self.config.get('interface_ids',[]);indices=self.config.get('interface_indices',[]);names=self.config.get('interface_names',[])
        selected=self._selected_keys() if self.choices else {ids[i].casefold() if i<len(ids) and ids[i] else str(index) for i,index in enumerate(indices)}
        rows=[dict(row) for row in links]
        for slot,index in enumerate(indices):
            identity=ids[slot] if slot<len(ids) else ''
            if not any((r.get('id','').casefold()==identity.casefold() if identity else r['index']==index) for r in rows):
                rows.append(dict(index=index,id=identity,name=names[slot] if slot<len(names) else f'Adapter {index}',description='Saved adapter · currently disconnected',up=False,addresses=[],gateway=''))
        while self.list_layout.count():
            item=self.list_layout.takeAt(0)
            if item.widget():item.widget().deleteLater()
        self.links=rows;self.choices=[]
        for link in rows:
            identity=link.get('id','').casefold() or str(link['index']);available=bool(link['up'] and link['addresses'] and link['gateway'])
            detail='Available · '+link['addresses'][0] if available else 'Offline · waiting for an address'
            choice=QCheckBox(f"{link['name']} · {detail}\n{link.get('description','')}");choice.setProperty('adapterIdentity',identity);choice.setChecked(identity in selected)
            choice.setEnabled(available or bool(link.get('id')));choice.setToolTip('Adapter '+str(link['index'])+' · '+link.get('id',''))
            choice.toggled.connect(self._selection_changed);self.choices.append((link['index'],choice));self.list_layout.addWidget(choice)
        self._selection_changed()

    def _selection_changed(self):
        count=sum(choice.isChecked() for _,choice in self.choices);self.selection_status.setText(f'{count} of 2 adapters selected')
        self.buttons.button(QDialogButtonBox.Save).setEnabled(count==2 and not self.worker.busy)

    def refresh(self):
        self.refresh_button.setEnabled(False);self.feedback.setText('Detecting physical adapters…')
        self.worker.start(discover_links);self._selection_changed()

    def _refreshed(self,links):
        self.refresh_button.setEnabled(True);self._set_links(links);self.feedback.setText('Addresses refreshed. Save to use this selection on your next connection.')

    def _refresh_failed(self,message):
        self.refresh_button.setEnabled(True);self._selection_changed();self.feedback.setText('Could not refresh adapters: '+message)

    def write_config(self):
        selected=[index for index,choice in self.choices if choice.isChecked()]
        ids=self.config.get('interface_ids',[])
        order={(ids[slot].casefold() if slot<len(ids) and ids[slot] else str(index)):slot for slot,index in enumerate(self.config['interface_indices'])}
        rows={r['index']:r for r in self.links}
        selected.sort(key=lambda index:order.get(rows[index].get('id','').casefold() or str(index),len(order)))
        if set(selected)==set(self.config['interface_indices']):selected=self.config['interface_indices']
        return save_selection(selected,links=self.links)


class LinkControlsDialog(SettingsDialog):
    def __init__(self,links,runtime=None,parent=None):
        super().__init__('Link roles and limits',parent);self.resize(680,690);self.fields={}
        self.body.addWidget(QLabel('Primary: always use · Secondary: boost when needed\nBackup: use after other links fail · Never: disabled'))
        scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setFrameShape(QScrollArea.NoFrame)
        content=QWidget();layout=QVBoxLayout(content);scroll.setWidget(content);self.body.addWidget(scroll,1)
        try:ledger=UsageLedger(ROOT/'.runtime/link-usage.json')
        except (ValueError,OSError):ledger=None
        for index in self.config['interface_indices']:
            key=str(index);policy=LinkPolicy(**self.config.get('link_policies',{}).get(key,{}))
            link=next((r for r in links if r['index']==index),None)
            group=QGroupBox(link['name'] if link else f'Adapter {index}');form=QFormLayout(group);layout.addWidget(group)
            usage=(runtime or {}).get('link_usage',{}).get(key) or (ledger.usage(key,policy) if ledger else None)
            if usage:form.addRow(QLabel(f"Today {human_bytes(usage['daily_bytes'])} · Billing cycle {human_bytes(usage['monthly_bytes'])}"))
            fields={}
            for name,title,value in (('role','Role',policy.role),('upload_mbps','Upload limit (Mbps)',policy.upload_mbps),
                ('download_mbps','Download limit (Mbps)',policy.download_mbps),('daily_bytes','Daily cap (GB)',policy.daily_bytes/1e9),
                ('monthly_bytes','Monthly cap (GB)',policy.monthly_bytes/1e9),('reset_day','Billing reset day',policy.reset_day),
                ('overlimit','At cap',policy.overlimit),('overlimit_mbps','Overlimit speed (Mbps)',policy.overlimit_mbps)):
                if name in ('role','overlimit'):
                    editor=QComboBox();editor.addItems(['primary','secondary','backup','never'] if name=='role' else ['stop','throttle']);editor.setCurrentText(value)
                elif name=='reset_day':editor=QSpinBox();editor.setRange(1,31);editor.setValue(value)
                else:
                    editor=QDoubleSpinBox();editor.setDecimals(3);editor.setRange(0,10000 if 'mbps' in name else 1000000);editor.setValue(value)
                fields[name]=editor;form.addRow(title,editor)
            self.fields[key]=fields
        self.feedback.setText('0 means no configured limit. GB = 1,000,000,000 bytes. Usage includes copies and repairs; allow headroom for in-flight traffic. Save and reconnect to apply.')

    def write_config(self):
        policies=dict(self.config.get('link_policies',{}))
        for key,fields in self.fields.items():
            values={name:(editor.currentText() if isinstance(editor,QComboBox) else editor.value()) for name,editor in fields.items()}
            for name in ('daily_bytes','monthly_bytes'):values[name]=int(values[name]*1e9)
            policies[key]=LinkPolicy(**values).to_dict()
        return save_link_policies(policies)
