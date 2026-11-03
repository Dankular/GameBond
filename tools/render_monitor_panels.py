"""Offscreen-only layout checks. Test fixtures are not product telemetry."""
import os
os.environ['QT_QPA_PLATFORM']='offscreen'

import json
import math
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from PyQt5.QtGui import QFont,QFontDatabase
from PyQt5.QtWidgets import QApplication
from gamebond.glass_panels import HardwarePanel,NetworkScannerPanel
from gamebond.network_scanner import DeviceHistory,normalize_inventory


def main():
    app=QApplication([]);app.setStyle('Fusion')
    font=ROOT/'assets/glasswire/Fonts/Roboto-Regular.ttf'
    if font.exists():QFontDatabase.addApplicationFont(str(font))
    app.setFont(QFont('Roboto',10))
    app.setStyleSheet('''QWidget {color:#5e6571;} QFrame#hardwareStatsFooter {background:white;}
        QLabel#hardwareStatTitle {color:#8b9198;font-size:12px;} QLabel#hardwareStatValue {color:#666c76;}
        QLabel#hardwareStatus {color:#a0a9aa;font-size:10px;} QFrame#scannerToolbar {background:#f6f6f6;border-bottom:1px solid #dddddd;}
        QComboBox,QLineEdit {background:white;border:1px solid #dddddd;border-radius:3px;padding:6px;}
        QPushButton#scannerScanButton {background:white;border:1px solid #dadada;border-radius:14px;padding:6px 18px;}
        QLabel#scannerScannedLabel {color:#a0a0a0;}''')
    sys.path.insert(0,str(ROOT/'tests'))
    from test_glass_panels import hardware_fixture
    hardware=hardware_fixture()
    hardware['history']=[dict(monotonic_time=1000+i,cpu_percent=max(0,12+8*math.sin(i/12)+4*math.cos(i/4)),
        memory_percent=40+i*.025,disk_read_bytes_s=max(0,1200000*math.sin(i/10)),
        disk_write_bytes_s=max(0,450000*math.sin(i/9)),gpu_percent=max(0,18+10*math.sin(i/20))) for i in range(301)]
    h=HardwarePanel(autostart=False);h._sample_ready(hardware);h.resize(1100,640);h.show()
    network=normalize_inventory(dict(adapters=[dict(index=25,name='Ethernet',address='192.168.1.93',prefix_length=24,up=True)],
        neighbors=[dict(interface_index=25,address='192.168.1.1',mac='ac-ef-00-12-34-56',state='Reachable'),
            dict(interface_index=25,address='192.168.1.42',mac='a0-b0-c0-d0-e0-f0',state='Stale')]))
    n=NetworkScannerPanel(autostart=False,history=DeviceHistory())
    network['devices']=n.history.observe(network['devices'],network['observed_at'])
    n._inventory_ready(network);n.resize(1100,640);n.show()
    for _ in range(5):app.processEvents();time.sleep(.01)
    directory=ROOT/'evidence/glasswire-ui';directory.mkdir(parents=True,exist_ok=True)
    outputs=[]
    for name,panel in (('monitors-hardware-offscreen',h),('monitors-scanner-offscreen',n)):
        path=directory/(name+'.png')
        if not panel.grab().save(str(path)):raise RuntimeError('Qt screenshot save failed')
        outputs.append(str(path))
        panel.shutdown();panel.close()
    report=dict(offscreen=True,data_source='Explicit deterministic UI test fixtures, not live telemetry',
        active_network_scan=False,outputs=outputs,panels='Tab content only; root owns main navigation and theme integration')
    (directory/'monitors-layout-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
