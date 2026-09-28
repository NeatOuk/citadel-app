"""Loads the app's QML offscreen and fails on any QML error or warning.

Catches syntax errors and broken bindings in Main.qml, the shims and every
view, and feeds a realistic state snapshot through ServiceClient so each tab
evaluates its bindings. Skipped when PySide6 is not importable (run it with
a Python that has PySide6, e.g. the system one after `pacman -S pyside6`).
"""
import json
import os
import sys
import unittest

try:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QObject, QTimer, QUrl, Property, Signal, Slot, qInstallMessageHandler, QtMsgType
    from PySide6.QtQml import QQmlApplicationEngine
    from PySide6.QtQuickControls2 import QQuickStyle
    from PySide6.QtWidgets import QApplication
    HAVE_QT = True
except ImportError:
    HAVE_QT = False

HERE = os.path.dirname(os.path.abspath(__file__))
QML = os.path.join(HERE, "..", "app", "qml")

SLICE = "user.slice/user-1000.slice/user@1000.service/app.slice/"
CONN = {"key": "k1", "exe": "/usr/bin/curl", "app": "curl", "raddr": "93.184.216.34", "rport": 443, "host": "example.com",
        "proto": "tcp", "cgroup": SLICE + "a.scope", "system": False, "scope": "internet", "new": True, "pid": 7,
        "up": 10, "down": 20, "upRate": 1, "downRate": 2, "list": "", "via": "speedtest", "viaId": "/home/u/bin/speedtest",
        "viaKind": "script", "cmd": "curl https://example.com", "cc": "US", "org": "Example Inc", "chain": ["speedtest"]}
STATE = {
    "rules": [{"id": "r1", "profile": "*", "app": "/usr/bin/curl", "via": "*", "host": "example.com", "port": "*",
               "action": "allow", "route": "p1", "duration": "forever", "pids": [], "exeHash": "", "note": "",
               "origin": "you", "createdAt": 100}],
    "conns": [CONN], "apps": {"/usr/bin/curl": {"name": "curl", "pids": [7], "cgroups": [SLICE + "a.scope"], "owned": [],
                                                "trust": {"level": "verified", "pkg": "curl", "hash": "h"}}},
    "groups": [{"key": "/usr/bin/curl", "app": "curl", "exe": "/usr/bin/curl", "system": False, "conns": [CONN], "via": "",
                "viaId": "", "viaKind": "", "up": 10, "down": 20, "upRate": 1, "downRate": 2, "denied": 0, "prompts": 1}],
    "decisions": {"k1": {"verdict": "prompt", "source": "none", "rule": None}},
    "alerts": [{"key": "a1", "conn": CONN, "firstSeen": 1000, "changed": False, "short": False,
                "trust": {"level": "verified"}, "hasOwnScope": True}],
    "proxies": [{"id": "p1", "name": "Office", "type": "http", "host": "192.168.1.3", "port": 8080, "listen": 47001,
                 "auth": False, "verifyTls": True}],
    "proxyStatus": {"p1": {"ok": True, "ms": 12, "error": "", "ts": 1000}},
    "proxyLog": [{"ts": 1000, "proxy": "Office", "dst": "1.2.3.4", "port": 443, "error": "refused"}],
    "recentShort": [{"conn": dict(CONN, key="s1", short=True, confidence="likely", ts=1000), "decision":
                     {"verdict": "prompt", "source": "none", "rule": None}, "count": 2}],
    "decisionLog": [{"ts": 1000, "app": "curl", "exe": "/usr/bin/curl", "via": "", "dest": "example.com", "ip": "93.184.216.34",
                     "port": 443, "cc": "US", "verdict": "allow", "source": "you · once"}],
    "profiles": [{"name": "Default", "networks": ["Home"]}], "network": {"names": ["Home"], "ssid": "Home"},
    "lists": [{"id": "stevenblack", "name": "StevenBlack", "kind": "domain", "url": "https://x", "enabled": True}],
    "installedAgents": ["claude", "pi"], "defaultAgent": "", "helperInstalled": True, "helperVersion": "1.3.0",
    "helperUsable": True, "proxyCapable": True, "enforce": True, "enforceActive": True, "monitorUp": True,
    "stats": {"series": [{"ts": 1000, "up": 1, "down": 2}], "topAppsToday": [{"name": "curl", "bytes": 30}],
              "topHostsToday": [{"name": "example.com", "bytes": 30}], "countriesToday": [{"name": "US", "bytes": 30}],
              "topApps7d": []},
}

if HAVE_QT:
    class FakeLink(QObject):
        message = Signal(str)
        connectedChanged = Signal()

        def __init__(self):
            super().__init__()
            self.sent = []

        @Slot(str)
        def send(self, text):
            self.sent.append(json.loads(text))

        def _c(self):
            return True
        connected = Property(bool, _c, notify=connectedChanged)

    class FakeControl(QObject):
        showRequested = Signal(str)
        modeRequested = Signal(str, int)
        changed = Signal()

        def __init__(self):
            super().__init__()
            self._s, self._w = "", 0

        def _gs(self):
            return self._s

        def _ss(self, v):
            self._s = v
        trayState = Property(str, _gs, _ss, notify=changed)

        def _gw(self):
            return self._w

        def _sw(self, v):
            self._w = v
        trayWaiting = Property(int, _gw, _sw, notify=changed)

    class FakeClip(QObject):
        @Slot(str)
        def copy(self, t):
            self.last = t

        @Slot(result=str)
        def paste(self):
            return "{}"


@unittest.skipUnless(HAVE_QT, "PySide6 not installed")
class QmlLoads(unittest.TestCase):
    def test_main_and_every_tab_load_without_warnings(self):
        problems = []

        def handler(mode, ctx, msg):
            # "portal": no desktop file in tests; "font family aliases": Qt's
            # offscreen platform on macOS asks for a "Sans Serif" font Macs
            # don't have (a one-off lookup cost, not a QML problem)
            benign = "portal" in msg or "Populating font family aliases" in msg
            if mode in (QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg) and not benign:
                problems.append(msg)
        qInstallMessageHandler(handler)
        QQuickStyle.setStyle("Fusion")
        app = QApplication.instance() or QApplication([sys.argv[0]])
        engine = QQmlApplicationEngine()
        engine.addImportPath(QML)
        link, control, clip = FakeLink(), FakeControl(), FakeClip()
        engine.rootContext().setContextProperty("daemonLink", link)
        engine.rootContext().setContextProperty("appControl", control)
        engine.rootContext().setContextProperty("clipboard", clip)
        engine.load(QUrl.fromLocalFile(os.path.join(QML, "Main.qml")))
        self.assertTrue(engine.rootObjects(), "\n".join(problems))
        win = engine.rootObjects()[0]
        link.message.emit(json.dumps({"type": "state", "full": True, "data": STATE}))
        for view in ("gate", "traffic", "policies", "history", "settings"):
            win.setProperty("view", view)
            for _ in range(5):
                app.processEvents()
        QTimer.singleShot(0, app.quit)
        app.exec()
        qInstallMessageHandler(None)
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertEqual(control.trayWaiting, 1)


if __name__ == "__main__":
    unittest.main()
