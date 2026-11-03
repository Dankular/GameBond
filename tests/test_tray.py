import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from gamebond.tray import AgentLease, TrayAgent
from gamebond.widget import Widget


class TrayTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','Windows agent instance coordination')
    def test_second_launch_signals_first_and_releasing_all_handles_allows_relaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            first=AgentLease(Path(directory));second=None;third=None
            try:
                self.assertTrue(first.owner)
                second=AgentLease(Path(directory));self.assertFalse(second.owner)
                self.assertTrue(first.show_requested());self.assertFalse(first.show_requested())
                second.close();first.close()
                third=AgentLease(Path(directory));self.assertTrue(third.owner)
            finally:
                first.close()
                if second:second.close()
                if third:third.close()

    def test_menu_queues_actions_and_status_changes_connect_to_disconnect(self):
        import pystray
        actions=[]
        with patch.object(pystray,'Icon') as icon:
            tray=TrayAgent(actions.append)
            menu=icon.call_args.kwargs['menu']
            menu.items[0](None)
            self.assertEqual(actions,['show'])
            self.assertEqual(menu.items[1].text,'Connect')
            tray.update(dict(state='running',peer=['195.154.119.136',4433],transport=dict(paths=[dict(healthy=True)])))
            self.assertEqual(menu.items[1].text,'Disconnect')
            tray.update(dict(state='connecting'),True)
            self.assertFalse(menu.items[1].enabled)
            broken=dict(state='running',peer=['195.154.119.136',4433],transport=dict(paths=[dict(healthy=True),dict(healthy=False)]))
            tray.update(broken)
            first=icon.return_value.icon
            tray.update(broken)
            self.assertIsNot(icon.return_value.icon,first)
            self.assertIn('Network problem',icon.return_value.title)
            tray.update(None)
            self.assertIs(icon.return_value.icon,tray.images['idle'])
            self.assertEqual(tray.images['idle'].getpixel((8,32)),(0,0,0,255))
            tray.close();icon.return_value.stop.assert_called_once()

    def test_close_hides_without_stopping_and_quit_waits_for_tunnel_stop(self):
        widget=object.__new__(Widget);widget.root=MagicMock();widget.tray=MagicMock(visible=True)
        widget.testing=False;widget.connect_pending=False;widget.toggle_tunnel=MagicMock()
        widget.close();widget.root.withdraw.assert_called_once();widget.root.destroy.assert_not_called()
        with patch('gamebond.widget.live_status',return_value={'state':'running'}):widget.quit()
        self.assertTrue(widget.quitting);widget.toggle_tunnel.assert_called_once()
        widget.root.destroy.assert_not_called()
