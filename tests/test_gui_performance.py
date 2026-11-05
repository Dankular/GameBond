"""Interaction and lifecycle regressions for GUI refresh performance."""
import json
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch,Mock

from PyQt5.QtCore import Qt,QTimer
from PyQt5.QtWidgets import QApplication,QTableWidget
from gamebond.glass_protect import ProtectPanel
from gamebond.glass_logs import EventJournal,LogPanel,_JournalWriter
from gamebond.glass_panels import _rows,HardwarePanel
from gamebond.glass_traffic import TrafficPanel

class GUIRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])

    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.config=Path(self.directory.name)/'config.json';self.config.write_text('{}')
        self.config_patch=patch('gamebond.glass_protect.CONFIG',self.config);self.config_patch.start()
        self.widgets=[]

    def tearDown(self):
        for widget in self.widgets:
            if hasattr(widget,'shutdown'):widget.shutdown()
            widget.close();widget.deleteLater()
        self.app.processEvents();self.config_patch.stop();self.directory.cleanup()

    def widget(self,widget):
        self.widgets.append(widget);return widget

    def runtime(self,count=1000):
        return dict(pid=1,state='running',peer=['203.0.113.1',4433],
            app_attribution=dict(available=True),transport=dict(paths=[dict(healthy=True)],rx_bytes=5000,tx_bytes=2000),
            application=dict(downloaded_bytes=count,uploaded_bytes=100),
            applications=[dict(path=r'C:\Apps\Browser.exe',name='Browser',pid=100,
            created_filetime='134000000000000000',generation=1,downloaded_bytes=count,
            uploaded_bytes=100,active_connections=1,destinations=['1.1.1.1:443'])])

    def test_live_refresh_preserves_selection_and_outbound_editor(self):
        panel=self.widget(ProtectPanel());panel.update_runtime(self.runtime())
        panel.table.selectRow(0);editor=panel.table.cellWidget(0,2)
        graph=panel.table.cellWidget(0,7);cell=panel.table.item(0,5)
        panel.update_runtime(self.runtime(3000))
        self.assertIs(panel.table.cellWidget(0,2),editor)
        self.assertIs(panel.table.cellWidget(0,7),graph)
        self.assertIs(panel.table.item(0,5),cell)
        self.assertEqual(panel.table.currentRow(),0)
        self.assertEqual(panel.current_path,r'c:\apps\browser.exe')

    def test_inactive_protect_keeps_sampling_and_renders_latest_on_activation(self):
        panel=self.widget(ProtectPanel());panel.set_active(False)
        with patch('gamebond.glass_protect.time.monotonic',side_effect=[10,12]):
            panel.update_runtime(self.runtime());panel.update_runtime(self.runtime(3000))
        self.assertEqual(panel.table.rowCount(),0)
        panel.set_active(True)
        self.assertEqual(panel.table.rowCount(),1)
        self.assertEqual(panel.table.item(0,5).text(),'1.0 KB/s')

    def test_removed_app_controls_do_not_survive_disconnect(self):
        panel=self.widget(ProtectPanel());panel.update_runtime(self.runtime())
        panel.table.selectRow(0);panel.update_runtime(None)
        self.assertEqual(panel.table.rowCount(),0);self.assertIsNone(panel.current_path)

    def test_graph_view_defers_tables_until_requested_and_clears_on_disconnect(self):
        panel=self.widget(TrafficPanel());panel.update_runtime(self.runtime())
        self.assertEqual(panel.app_table.rowCount(),0)
        panel.views.setCurrentIndex(1)
        self.assertEqual(panel.app_table.item(0,0).text(),'Browser')
        with patch('gamebond.glass_traffic.time.monotonic',return_value=panel.last_sample+1):
            panel.update_runtime(None)
        self.assertEqual(panel.app_table.rowCount(),0);self.assertEqual(panel.host_table.rowCount(),0)

    def test_resource_table_reuses_items_without_losing_selection(self):
        table=self.widget(QTableWidget(0,2));_rows(table,[('App',10)])
        item=table.item(0,1);table.selectRow(0)
        _rows(table,[('App',20)])
        self.assertIs(table.item(0,1),item);self.assertEqual(item.text(),'20')
        self.assertEqual(table.currentRow(),0)

    def test_hardware_timer_pauses_and_resumes_with_page_activity(self):
        sampler=Mock();panel=self.widget(HardwarePanel(sampler=sampler))
        with patch.object(panel,'refresh') as refresh:
            panel.set_active(False);self.assertFalse(panel.timer.isActive())
            panel.set_active(True);self.assertTrue(panel.timer.isActive())
            refresh.assert_called_once()
            panel.set_active(True);refresh.assert_called_once()
        panel.set_active(False)

    def test_event_batch_is_persisted_once_and_survives_reload(self):
        path=Path(self.directory.name)/'events.json';journal=EventJournal(path)
        events=[dict(id=i,timestamp=100+i,application=dict(path=fr'C:\Apps\app{i}.exe',name=f'App {i}'),
                     destination='1.1.1.1:443') for i in range(1,31)]
        with patch.object(journal,'save',wraps=journal.save) as save:
            self.assertTrue(journal.ingest(events));save.assert_called_once()
            self.assertFalse(journal.ingest(events));save.assert_called_once()
        restored=EventJournal(path);self.assertEqual(len(restored.events),30)

    def test_hidden_log_still_persists_events_then_renders_when_selected(self):
        journal=EventJournal(Path(self.directory.name)/'log.json')
        panel=self.widget(LogPanel(journal=journal));panel.set_active(False)
        event=dict(id=800,timestamp=100,application=dict(path=r'C:\Apps\probe.exe',name='Probe'),destination='1.1.1.1:443')
        runtime=self.runtime();runtime['app_events']=dict(events=[event])
        with patch.object(panel,'_icon',return_value=Mock()) as icon:
            panel.update_runtime(runtime);icon.assert_not_called()
        self.assertTrue(any(e['application'].get('name')=='Probe' for e in journal.events))
        panel.set_active(True)
        self.assertGreater(panel.rows.count(),1)

    def test_slow_journal_write_does_not_block_qt_and_latest_snapshot_is_flushed(self):
        parent=self.widget(QTableWidget());entered=threading.Event();release=threading.Event();writes=[]
        def slow_write(path,payload):
            writes.append(payload)
            if payload=='first':entered.set();release.wait(2)
        writer=_JournalWriter(parent)
        with patch('gamebond.glass_logs._write_journal',side_effect=slow_write):
            try:
                writer.submit(Path(self.directory.name)/'journal.json','first')
                self.assertTrue(entered.wait(1))
                writer.submit(Path(self.directory.name)/'journal.json','intermediate')
                writer.submit(Path(self.directory.name)/'journal.json','latest')
                heartbeat=threading.Event();QTimer.singleShot(0,heartbeat.set);self.app.processEvents()
                self.assertTrue(heartbeat.is_set());self.assertFalse(release.is_set())
            finally:release.set();writer.shutdown()
        self.assertEqual(writes,['first','latest'])
        self.assertFalse(writer.thread.is_alive())

    def test_log_updates_reuse_existing_cards_and_refresh_unread_state(self):
        journal=EventJournal(Path(self.directory.name)/'cards.json')
        panel=self.widget(LogPanel(journal=journal))
        journal.append('probe:first','connection_state','Connected',timestamp=100)
        panel.refresh();key=(journal.sequence,True);card=panel.cards[key]
        journal.append('probe:second','connection_state','Link recovered',timestamp=101)
        panel.refresh();self.assertIs(panel.cards[key],card)
        panel.mark_read()
        self.assertIn((key[0],False),panel.cards)

if __name__=='__main__':unittest.main()
