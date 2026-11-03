import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock,patch

try:
    from PyQt5.QtCore import QObject,pyqtSignal
    from PyQt5.QtWidgets import QApplication,QWidget
    from gamebond.glass_dashboard import GlassDashboard,BackendController,NewAppCursor
except ImportError:
    QApplication=None


def event(number):
    return dict(id=number,kind='new_app_tunnel_use',timestamp=time.time(),application=dict(path='C:/Apps/browser.exe',name='Browser',pid=99,created_filetime='133900000000000000'),
        proof='tcp_connect',protocol='tcp',destination='1.1.1.1:443',attribution='native_capture_owner_and_tunnel_success')


def runtime(events=None):
    return dict(pid=88,state='running',peer=['195.154.119.136',4433],capture_mode='all',
        transport=dict(paths=[dict(healthy=True),dict(healthy=True)]),
        app_events=dict(latest_id=6,events=events or []),
        app_attribution=dict(available=True,source='native_capture_owner_and_tunnel_success',history_error=None))


@unittest.skipUnless(QApplication is not None,'Optional Qt dashboard dependency')
class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QApplication.instance() or QApplication([]);cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        class Controller(QObject):
            stateChanged=pyqtSignal(object,object);error=pyqtSignal(str);busyChanged=pyqtSignal(bool);stopped=pyqtSignal()
            def __init__(self):
                super().__init__();self.initialized=True;self.busy=False;self.command=None
                self.toggle=Mock();self.stop=Mock(return_value=True);self.shutdown=Mock()
        class Panel(QWidget):
            def __init__(self):super().__init__();self.update_runtime=Mock();self.shutdown=Mock()
        self.controller=Controller();self.toasts=Mock()
        self.window=GlassDashboard(controller=self.controller,panel_factories=[Panel]*5,
            toast_factory=lambda *args:self.toasts,tray_enabled=False)
        self.window.cursor=NewAppCursor(latest=5)

    def tearDown(self):
        self.window._finish_close();self.app.processEvents()

    def test_six_tabs_are_real_panels_and_attach_does_not_connect(self):
        self.assertEqual(self.window.views.count(),6);self.assertEqual(len(self.window.nav),6)
        self.controller.toggle.assert_not_called()
        self.controller.stateChanged.emit(runtime(),{'links':[]})
        self.assertEqual(self.window.connect_button.text(),'Disconnect')
        self.assertIn('2/2',self.window.status.text())
        for panel in self.window.panels[:3]:panel.update_runtime.assert_called_once()
        self.window.select_tab(4);self.assertEqual(self.window.views.currentIndex(),4)
        self.window.select_tab(5);self.assertEqual(self.window.views.currentIndex(),5)

    def test_problem_flashes_amber_and_normal_disconnect_is_black(self):
        current=runtime();current['transport']['paths'][1]['healthy']=False
        self.controller.stateChanged.emit(current,{})
        self.assertIn('Degraded connection',self.window.status.text())
        first=self.window.tray.icon().cacheKey();self.window._tray_tick()
        self.assertNotEqual(first,self.window.tray.icon().cacheKey())
        self.assertIn('Network problem',self.window.tray.toolTip())
        self.controller.stateChanged.emit(None,{})
        self.assertEqual(self.window.tray.icon().cacheKey(),self.window.icons['disconnected'].cacheKey())

    def test_new_app_toasts_require_fresh_native_success_and_do_not_replay(self):
        self.controller.stateChanged.emit(runtime([event(5),event(6)]),{})
        self.toasts.push.assert_called_once();self.assertEqual(self.toasts.push.call_args.args[0]['id'],6)
        self.controller.stateChanged.emit(runtime([event(6)]),{});self.toasts.push.assert_called_once()

    def test_close_hides_and_quit_waits_for_stop_but_reload_preserves_tunnel(self):
        self.window.tray_available=True;self.window.close()
        self.controller.stop.assert_not_called();self.assertFalse(self.window._final_close)
        self.window.quit();self.controller.stop.assert_called_once();self.assertFalse(self.window._final_close)
        self.controller.stopped.emit();self.assertTrue(self.window._final_close)

    def test_reload_never_requests_tunnel_stop(self):
        self.window.reload_interface()
        self.controller.stop.assert_not_called();self.assertTrue(self.window.reload_requested)

    def test_network_controls_are_visible_and_offline_link_does_not_connect(self):
        links=[dict(index=25,id='',name='Starlink',up=True,addresses=['192.168.1.93'],gateway='192.168.1.1'),dict(index=16,id='',name='iPhone',up=False,addresses=[],gateway='')]
        self.window.config=dict(interface_indices=[25,16]);self.window.resize(860,560);self.window.show()
        self.controller.stateChanged.emit(None,dict(links=links,rates={}));self.app.processEvents()
        self.assertTrue(self.window.network_button.isVisible());self.assertTrue(self.window.link_limits_button.isVisible())
        self.assertEqual(self.window.nav[-1].text(),'DNS')
        self.assertEqual(self.window.network_labels[1][0].text(),'iPhone');self.assertIn('Offline',self.window.network_labels[1][1].text())
        self.assertLess(self.window.network_button.mapTo(self.window,self.window.network_button.rect().bottomRight()).y(),self.window.height())
        with patch.object(self.window,'_dialog') as opened:
            self.window.network_button.click();dialog=opened.call_args.args[0];self.assertIn('Select networks',dialog.windowTitle());dialog.reject();dialog.deleteLater()
        self.controller.toggle.assert_not_called()


@unittest.skipUnless(QApplication is not None,'Optional Qt dashboard dependency')
class CursorAndControllerTests(unittest.TestCase):
    def test_connecting_can_be_cancelled_without_waiting_for_timeout(self):
        app=QApplication.instance() or QApplication([])
        monitor=Mock();monitor.stop=threading.Event()
        controller=BackendController(monitor=monitor,autostart=False)
        try:
            controller.initialized=True;controller.command='start'
            with patch.object(controller,'stop',return_value=True) as stop:
                controller.toggle();stop.assert_called_once()
        finally:controller.shutdown()
    def test_cursor_bootstrap_uses_persisted_sequence_and_rejects_unproven_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'history.json';path.write_text(json.dumps(dict(sequence=5)))
            cursor=NewAppCursor(path)
            current=runtime([event(6)]);current['app_attribution']['available']=False
            self.assertEqual(cursor.observe(current),[])
            current['app_attribution']['available']=True
            self.assertEqual(cursor.observe(current),[]) # Never replay an old batch after attribution becomes available.
            current['app_events']=dict(latest_id=7,events=[{**event(7),'proof':'unknown'}])
            self.assertEqual(cursor.observe(current),[])

    def test_polling_uses_worker_and_never_connects_on_construction(self):
        app=QApplication.instance() or QApplication([])
        monitor=Mock();monitor.stop=threading.Event();monitor.snapshot.return_value={'links':[]}
        controller=BackendController(monitor=monitor,autostart=False)
        observed=[];main=threading.get_ident()
        def status():observed.append(threading.get_ident());return runtime()
        try:
            with patch('gamebond.glass_dashboard.live_status',side_effect=status),patch('subprocess.Popen') as popen:
                controller.poll();deadline=time.monotonic()+2
                while not controller.initialized and time.monotonic()<deadline:app.processEvents();time.sleep(.005)
                self.assertTrue(controller.initialized);popen.assert_not_called()
                self.assertNotEqual(observed[0],main)
        finally:controller.shutdown()
