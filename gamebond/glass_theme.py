"""Render recovered GlassWire Qt assets using their original theme variables."""
from functools import lru_cache
import json
from pathlib import Path
import re

from PyQt5.QtCore import QByteArray, Qt
from PyQt5.QtGui import QColor, QFontDatabase, QIcon, QPainter, QPixmap
from PyQt5.QtSvg import QSvgRenderer

ROOT=Path(__file__).resolve().parents[1]
ASSETS=ROOT/'assets/glasswire'


class GlassTheme:
    def __init__(self,name='light'):
        if name not in ('light','asphalt','neon'):raise ValueError('Unknown theme')
        self.name=name;self.values=json.loads((ASSETS/'Skins'/(name+'.json')).read_text())['colors']
        self.dark=name!='light'

    def color(self,key,state=None,fallback='#808080'):
        value=self.values.get(key+(('.'+state) if state else ''),self.values.get(key,fallback))
        if not value:return QColor(0,0,0,0)
        if value.startswith('rgba '):
            channels,alpha=value[5:].split(',');r,g,b=map(int,channels.split())
            return QColor(r,g,b,round(float(alpha)*255))
        color=QColor(value)
        return color if color.isValid() else QColor(fallback)

    def css(self,key,state=None,fallback='#808080'):
        color=self.color(key,state,fallback)
        return f'rgba({color.red()},{color.green()},{color.blue()},{color.alpha()})'

    @lru_cache(maxsize=512)
    def svg(self,path,state='n'):
        source=(ASSETS/path).read_text(encoding='utf-8')
        def replace(match):
            key=match.group(1);opacity=key.endswith('#opacity')
            if opacity:key=key[:-8]
            color=self.color(key,state)
            return str(color.alphaF()) if opacity else color.name()
        return re.sub(r'\$\(([^)]+)\)',replace,source).encode()

    @lru_cache(maxsize=256)
    def icon(self,path,state='n',size=20):
        pixmap=QPixmap(size,size);pixmap.fill(Qt.transparent)
        renderer=QSvgRenderer(QByteArray(self.svg(path,state)))
        painter=QPainter(pixmap);renderer.render(painter);painter.end()
        return QIcon(pixmap)

    def stylesheet(self):
        bg=self.css('gw_mainbg');text=self.css('gw_maintxt');secondary=self.css('on_srf_s2')
        panel=self.css('actionbar_bg');line=self.css('graph_bottomline')
        return f'''
        QWidget {{color:{text};font-family:Roboto;font-size:12px;}}
        QMainWindow, QDialog {{background:{bg};}}
        QPushButton,QComboBox {{background:{bg};border:1px solid {line};border-radius:14px;padding:6px 12px;}}
        QPushButton:hover,QComboBox:hover {{background:{self.css('actionbar_btn_bg','o')};}}
        QPushButton:disabled {{color:{secondary};}}
        QLineEdit {{border:0;border-radius:14px;background:{self.css('search_bg',fallback='#eceef2')};padding:7px 12px;}}
        QTableWidget,QTreeWidget {{background:{bg};alternate-background-color:{self.css('fw_top_area_bg')};border:0;gridline-color:{line};selection-background-color:{self.css('primary_s3')};}}
        QHeaderView::section {{background:{bg};color:{secondary};font-size:11px;border:0;border-right:1px solid {line};border-bottom:1px solid {line};padding:7px;}}
        QScrollBar:vertical {{background:transparent;width:9px;margin:0;}}
        QScrollBar::handle:vertical {{background:#c6c8cb;border-radius:4px;min-height:22px;}}
        QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{height:0;}}
        QMenu {{background:{bg};border:1px solid {line};padding:5px;}}
        QMenu::item {{padding:7px 22px;}}
        QMenu::item:selected {{background:{self.css('primary_s3')};}}
        QToolTip {{background:{panel};color:{text};border:1px solid {line};}}
        '''


def load_fonts():
    for path in (ASSETS/'Fonts').glob('*'):
        if path.suffix in ('.ttf','.otf'):QFontDatabase.addApplicationFont(str(path))
