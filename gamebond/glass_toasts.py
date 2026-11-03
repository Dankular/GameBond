"""Qt desktop notifications using the recovered 373x169 popup artwork."""
from collections import deque
from datetime import datetime
from pathlib import Path

from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QPoint, QByteArray, pyqtSignal
from PyQt5.QtGui import QPainter, QFont
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QFileIconProvider, QApplication
from PyQt5.QtCore import QFileInfo

from .glass_theme import GlassTheme


class AppToast(QWidget):
    activated=pyqtSignal(dict)
    dismissed=pyqtSignal(object)
    def __init__(self,event,theme=None,parent=None):
        super().__init__(parent,Qt.Tool|Qt.FramelessWindowHint|Qt.WindowStaysOnTopHint|Qt.WindowDoesNotAcceptFocus)
        self.setAttribute(Qt.WA_TranslucentBackground);self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setFixedSize(373,169);self.event=event;self.theme=theme or GlassTheme()
        self.background=QSvgRenderer(QByteArray(self.theme.svg('TrayPopups/popup-background.svg')),self)
        self.setStyleSheet(f'QLabel{{color:{self.theme.css("gw_popup_main_txt")};background:transparent;font-family:Roboto;font-size:12px;}}'
                          'QPushButton{background:transparent;border:0;}')
        title=QLabel('NEW TUNNEL ACTIVITY',self);title.setGeometry(20,15,295,20)
        title.setStyleSheet(f'color:{self.theme.css("gw_popup_secondary_txt")};font-size:10px;')
        close=QPushButton('×',self);close.setGeometry(337,10,26,26);close.setStyleSheet('color:#969da6;font-size:20px;')
        close.clicked.connect(self.close)
        application=event.get('application',{});path=application.get('path','')
        icon=QFileIconProvider().icon(QFileInfo(path)) if path else QApplication.style().standardIcon(1)
        image=QLabel(self);image.setPixmap(icon.pixmap(32,32));image.setGeometry(20,49,36,36)
        name=QLabel(application.get('name') or Path(path).name or 'Application',self)
        name.setGeometry(68,48,270,23);name.setFont(QFont('Roboto',12,QFont.Medium));name.setToolTip(path)
        description=QLabel('Used your tunnel for the first time',self);description.setGeometry(68,73,285,20)
        description.setStyleSheet(f'color:{self.theme.css("popup_txt_description")};font-size:11px;')
        destination=event.get('destination','')
        if isinstance(destination,(list,tuple)):destination=':'.join(map(str,destination))
        endpoint=QLabel(str(destination),self);endpoint.setGeometry(20,110,270,20)
        endpoint.setStyleSheet(f'color:{self.theme.css("popup_txt_description")};font-size:11px;')
        details=QPushButton('Details  ›',self);details.setGeometry(280,132,75,25)
        details.setStyleSheet(f'color:{self.theme.css("popup_actions_txt","n")};font-family:Roboto;font-size:11px;')
        details.clicked.connect(lambda:self.activated.emit(self.event))
        timestamp=QLabel(datetime.fromtimestamp(event.get('timestamp',0)).strftime('%H:%M'),self)
        timestamp.setGeometry(20,135,100,18);timestamp.setStyleSheet('color:#a1aab9;font-size:10px;')
        self.timer=QTimer(self);self.timer.setSingleShot(True);self.timer.timeout.connect(self.close)
        self.animation=QPropertyAnimation(self,b'pos',self);self.animation.setDuration(180)

    def paintEvent(self,event):
        painter=QPainter(self);self.background.render(painter)

    def reveal(self,position):
        self.move(position+QPoint(400,0));self.show()
        self.animation.setStartValue(self.pos());self.animation.setEndValue(position);self.animation.start()
        self.timer.start(8000)

    def enterEvent(self,event):self.timer.stop()
    def leaveEvent(self,event):self.timer.start(4000)
    def closeEvent(self,event):
        self.timer.stop();self.dismissed.emit(self);super().closeEvent(event)


class ToastManager:
    def __init__(self,activate,theme=None):
        self.activate=activate;self.theme=theme or GlassTheme();self.visible=[];self.pending=deque(maxlen=64);self.enabled=True

    def push(self,event):
        if not self.enabled:return
        self.pending.append(event);self._fill()

    def _fill(self):
        while self.pending and len(self.visible)<3:
            toast=AppToast(self.pending.popleft(),self.theme)
            toast.activated.connect(self.activate);toast.dismissed.connect(self._closed)
            self.visible.append(toast);toast.reveal(self._position(len(self.visible)-1))

    def _position(self,index):
        area=QApplication.primaryScreen().availableGeometry()
        return QPoint(area.right()-373-16,area.bottom()-(index+1)*181-8)

    def _closed(self,toast):
        if toast in self.visible:self.visible.remove(toast)
        toast.deleteLater()
        for index,other in enumerate(self.visible):other.move(self._position(index))
        QTimer.singleShot(0,self._fill)

    def close(self):
        self.enabled=False;self.pending.clear()
        for toast in list(self.visible):toast.close()
