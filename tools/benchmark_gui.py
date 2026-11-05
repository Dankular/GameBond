"""Offscreen Protect refresh benchmark; never connects or changes live settings."""
import json
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from pathlib import Path
import statistics
import sys
import tempfile
import time
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from PyQt5.QtWidgets import QApplication
from gamebond.glass_protect import ProtectPanel

def main():
    app=QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'config.json';path.write_text('{}')
        with patch('gamebond.glass_protect.CONFIG',path):panel=ProtectPanel()
        panel.resize(1120,700);panel.show();app.processEvents()
        rows=[dict(path=fr'C:\Apps\app{i}.exe',name=f'App {i:03}',pid=i+100,
            created_filetime='134000000000000000',generation=1,downloaded_bytes=1000,
            uploaded_bytes=100,active_connections=1,destinations=['1.1.1.1:443']) for i in range(128)]
        runtime=dict(pid=1,state='running',applications=rows,app_attribution=dict(available=True))
        samples=[]
        for tick in range(9):
            for row in rows:row['downloaded_bytes']+=1024;row['uploaded_bytes']+=64
            start=time.perf_counter();panel.update_runtime(runtime);app.processEvents()
            samples.append((time.perf_counter()-start)*1000)
        report=dict(rows=len(rows),cold_ms=round(samples[0],2),
            median_refresh_ms=round(statistics.median(samples[1:]),2),max_refresh_ms=round(max(samples[1:]),2))
        panel.close();panel.deleteLater();app.processEvents()
        print(json.dumps(report))

if __name__=='__main__':main()
