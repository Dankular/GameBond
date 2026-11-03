import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import json
from pathlib import Path
import tempfile
import unittest

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPixmap

from gamebond.glass_theme import GlassTheme,load_fonts
from gamebond.glass_toasts import AppToast
from gamebond.glass_logs import EventJournal,LogPanel
from gamebond.glass_traffic import TrafficPanel


class GlassUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([]);load_fonts()

    def test_recovered_svg_theme_tokens_render_without_unresolved_placeholders(self):
        for name in ('light','asphalt','neon'):
            theme=GlassTheme(name)
            for asset in ('MainTopPanel/ico-top-graph.svg','TrayPopups/popup-background.svg'):
                self.assertNotIn(b'$(',theme.svg(asset))
            self.assertFalse(theme.icon('MainTopPanel/ico-top-graph.svg').isNull())

    def test_toast_uses_original_dimensions_and_renders_offscreen(self):
        toast=AppToast(dict(kind='preview',timestamp=1,application=dict(name='Diagnostic'),destination='127.0.0.1:443'))
        try:
            self.assertEqual((toast.width(),toast.height()),(373,169))
            image=QPixmap(toast.size());toast.render(image);self.assertFalse(image.isNull())
        finally:toast.deleteLater()

    def test_history_deduplicates_app_events_and_retains_read_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events.json';journal=EventJournal(path)
            event=dict(id=1,timestamp=1234,application=dict(name='Example',path=r'C:\Apps\example.exe'),destination='127.0.0.1:443')
            self.assertTrue(journal.ingest([event]));self.assertFalse(journal.ingest([event]))
            journal.read_through=journal.sequence;journal.save()
            restored=EventJournal(path);self.assertEqual(len(restored.events),1);self.assertEqual(restored.read_through,1)
            panel=LogPanel(journal=restored);panel.search.setText('missing');panel.refresh();panel.deleteLater()

    def test_corrupt_history_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events.json';path.write_text('{broken')
            journal=EventJournal(path);self.assertTrue(journal.error)
            journal.append('one','connection_state','Disconnected')
            self.assertEqual(path.read_text(),'{broken')

    def test_traffic_reads_verified_payload_counters_without_adapter_sum(self):
        panel=TrafficPanel()
        try:
            runtime=dict(pid=123,state='running',peer=['195.154.119.136',4433],transport=dict(rx_bytes=5000,tx_bytes=4000,paths=[dict(healthy=True)]),
                         application=dict(downloaded_bytes=1024,uploaded_bytes=500),applications=[])
            panel.update_runtime(runtime)
            self.assertIn('1.0 KB',panel.down.text());self.assertIn('Application payload',panel.caption.text())
        finally:panel.deleteLater()
