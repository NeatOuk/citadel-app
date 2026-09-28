"""citadel-app: Citadel's window and tray icon (PySide6 + QML).

The window is a front-end of citadel-daemon: everything it shows comes from
the daemon's socket, and every action goes back to it. Closing the window
keeps the tray icon; the daemon keeps enforcing either way.

Single instance: a second launch asks the first to show itself (with
`--gate`, on the Gate tab) and exits.
"""
import argparse
import os
import sys

from PySide6.QtCore import (QByteArray, QObject, QPointF, QRectF, Qt, QTimer, QUrl, Property, Signal, Slot)
from PySide6.QtGui import QAction, QColor, QGuiApplication, QIcon, QPainter, QPainterPath, QPen, QPixmap, QFont
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle
from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon

HERE = os.path.dirname(os.path.abspath(__file__))
QML_DIR = os.environ.get("CITADEL_QML_DIR") or os.path.join(HERE, "qml")


def runtime_dir():
    base = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
    return os.environ.get("CITADEL_RUNTIME_DIR") or os.path.join(base, "citadel")


class DaemonLink(QObject):
    """JSON lines to and from citadel-daemon's Unix socket; reconnects on its own."""
    message = Signal(str)
    connectedChanged = Signal()

    def __init__(self, path):
        super().__init__()
        self.path = path
        self.sock = QLocalSocket(self)
        self.buf = b""
        self._connected = False
        self.sock.connected.connect(self._on_connected)
        self.sock.disconnected.connect(self._on_disconnected)
        self.sock.readyRead.connect(self._on_ready)
        self.sock.errorOccurred.connect(lambda _e: self._set_connected(False))
        self.timer = QTimer(self, interval=2000)
        self.timer.timeout.connect(self._try)
        self.timer.start()
        self._try()

    def _try(self):
        if self.sock.state() == QLocalSocket.LocalSocketState.UnconnectedState:
            self.sock.connectToServer(self.path)

    def _set_connected(self, v):
        if v != self._connected:
            self._connected = v
            self.connectedChanged.emit()

    def _on_connected(self):
        self.buf = b""
        self._set_connected(True)

    def _on_disconnected(self):
        self._set_connected(False)

    def _on_ready(self):
        self.buf += bytes(self.sock.readAll())
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            if line:
                self.message.emit(line.decode("utf-8", "replace"))

    @Slot(str)
    def send(self, text):
        if self._connected:
            self.sock.write(QByteArray((text + "\n").encode()))
            self.sock.flush()

    def _get_connected(self):
        return self._connected
    connected = Property(bool, _get_connected, notify=connectedChanged)


class Clipboard(QObject):
    @Slot(str)
    def copy(self, text):
        QGuiApplication.clipboard().setText(text)

    @Slot(result=str)
    def paste(self):
        return QGuiApplication.clipboard().text()


def tower_icon(mode="guarded", waiting=0, dim=False, size=64):
    """Citadel's tower for the tray: the gate shows the mode, a badge counts requests."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    fg = QColor("#9aa0a6" if dim else "#e8eaed")
    s = size / 64.0
    body = QPainterPath()
    # keep with three battlements
    body.moveTo(12 * s, 58 * s)
    body.lineTo(12 * s, 14 * s)
    for x in (12, 26, 40):
        body.lineTo(x * s, 6 * s)
        body.lineTo((x + 8) * s, 6 * s)
        body.lineTo((x + 8) * s, 14 * s)
        body.lineTo((x + 14) * s, 14 * s)
    body.lineTo(52 * s, 58 * s)
    body.closeSubpath()
    p.fillPath(body, fg)
    # gate arch
    gate = QPainterPath()
    gate.moveTo(24 * s, 58 * s)
    gate.lineTo(24 * s, 40 * s)
    gate.arcTo(QRectF(24 * s, 30 * s, 16 * s, 20 * s), 180, -180)
    gate.lineTo(40 * s, 58 * s)
    gate.closeSubpath()
    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
    if mode != "guarded":
        p.fillPath(gate, Qt.GlobalColor.transparent)
    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
    if mode == "lockdown":
        pen = QPen(fg, 2.5 * s)
        p.setPen(pen)
        for x in (28, 32, 36):
            p.drawLine(QPointF(x * s, 34 * s), QPointF(x * s, 58 * s))
    if waiting:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#e06c6c"))
        p.drawEllipse(QRectF(36 * s, 34 * s, 28 * s, 28 * s))
        p.setPen(QColor("white"))
        f = QFont()
        f.setBold(True)
        f.setPixelSize(int(18 * s))
        p.setFont(f)
        p.drawText(QRectF(36 * s, 34 * s, 28 * s, 28 * s), Qt.AlignmentFlag.AlignCenter, str(min(waiting, 99)))
    p.end()
    return QIcon(pm)


class AppControl(QObject):
    """Tray icon, single-instance server, and the window's show requests."""
    showRequested = Signal(str)
    modeRequested = Signal(str, int)
    trayChanged = Signal()

    def __init__(self, app):
        super().__init__()
        self.app = app
        self._state, self._waiting = "guarded", 0
        self.tray = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(tower_icon(), app)
            self.tray.setToolTip("Citadel")
            menu = QMenu()
            for label, cb in (("Open Citadel", lambda: self.showRequested.emit("")),
                              ("Gate", lambda: self.showRequested.emit("gate")),
                              (None, None),
                              ("Guarded", lambda: self.modeRequested.emit("guarded", 0)),
                              ("Open for 1 hour", lambda: self.modeRequested.emit("open", 60)),
                              ("Lockdown", lambda: self.modeRequested.emit("lockdown", 0)),
                              (None, None),
                              ("Quit window (the service keeps running)", app.quit)):
                if label is None:
                    menu.addSeparator()
                else:
                    a = QAction(label, menu)
                    a.triggered.connect(cb)
                    menu.addAction(a)
            self.menu = menu
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._activated)
            self.tray.show()

    def _activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.showRequested.emit("gate" if self._waiting else "")

    def _refresh(self):
        if self.tray:
            mode, _, watching = self._state.partition(":")
            self.tray.setIcon(tower_icon(mode, self._waiting, dim=bool(watching)))
            self.tray.setToolTip("Citadel · %s%s" % (mode, " · %d at the gate" % self._waiting if self._waiting else ""))

    def _get_state(self):
        return self._state

    def _set_state(self, v):
        if v != self._state:
            self._state = v
            self._refresh()
            self.trayChanged.emit()
    trayState = Property(str, _get_state, _set_state, notify=trayChanged)

    def _get_waiting(self):
        return self._waiting

    def _set_waiting(self, v):
        if v != self._waiting:
            self._waiting = v
            self._refresh()
            self.trayChanged.emit()
    trayWaiting = Property(int, _get_waiting, _set_waiting, notify=trayChanged)

    @property
    def has_tray(self):
        return self.tray is not None


def ask_running_instance(path, view):
    s = QLocalSocket()
    s.connectToServer(path)
    if not s.waitForConnected(500):
        return False
    s.write(QByteArray(("show %s\n" % view).encode()))
    s.flush()
    s.waitForBytesWritten(500)
    s.disconnectFromServer()
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(prog="citadel-app")
    ap.add_argument("--gate", action="store_true", help="open on the Gate tab")
    ap.add_argument("--hidden", action="store_true", help="start in the tray (e.g. at login)")
    ap.add_argument("--view", default="", help="gate | traffic | policies | history | settings")
    a, qt_args = ap.parse_known_args(argv)
    view = "gate" if a.gate else a.view

    QApplication.setApplicationName("Citadel")
    QApplication.setDesktopFileName("io.github.neatouk.Citadel")
    QQuickStyle.setStyle("Fusion")
    app = QApplication([sys.argv[0]] + qt_args)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(tower_icon())

    rdir = runtime_dir()
    os.makedirs(rdir, mode=0o700, exist_ok=True)
    inst_path = os.path.join(rdir, "app.sock")
    if ask_running_instance(inst_path, view or "-"):
        return 0
    QLocalServer.removeServer(inst_path)
    inst = QLocalServer()
    inst.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    inst.listen(inst_path)

    link = DaemonLink(os.path.join(rdir, "daemon.sock"))
    control = AppControl(app)
    clip = Clipboard()

    def on_instance():
        c = inst.nextPendingConnection()

        def read():
            for line in bytes(c.readAll()).decode(errors="replace").splitlines():
                if line.startswith("show"):
                    v = line[5:].strip()
                    control.showRequested.emit("" if v == "-" else v)
        c.readyRead.connect(read)
    inst.newConnection.connect(on_instance)

    engine = QQmlApplicationEngine()
    engine.addImportPath(QML_DIR)
    ctx = engine.rootContext()
    ctx.setContextProperty("daemonLink", link)
    ctx.setContextProperty("appControl", control)
    ctx.setContextProperty("clipboard", clip)
    engine.load(QUrl.fromLocalFile(os.path.join(QML_DIR, "Main.qml")))
    if not engine.rootObjects():
        return 1
    win = engine.rootObjects()[0]
    if view:
        win.setProperty("view", view)
    if not (a.hidden and control.has_tray):
        win.show()
    # without a tray, closing the window quits the app (the daemon keeps running)
    if not control.has_tray:
        app.setQuitOnLastWindowClosed(True)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
