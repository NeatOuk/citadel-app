"""The daemon's socket API: JSON lines over a Unix socket.

Socket: $XDG_RUNTIME_DIR/citadel/daemon.sock (dir 0700, socket 0600). Only
the daemon's own user may connect (checked with SO_PEERCRED).

Client -> daemon:  {"id": 1, "cmd": "answer", "args": [key, "allow", "host", "forever"]}
Daemon -> client:  {"type": "reply", "id": 1, "ok": true, "result": ...}
                   {"type": "state", "data": {...}}   full on connect, then changed keys
                   {"type": "open", "view": "gate"}   a notification asked for the window
"""
import asyncio
import json
import logging
import os
import socket
import struct

log = logging.getLogger("citadel.api")

# daemon methods a front-end may call
COMMANDS = {
    "answer", "addRule", "updateRule", "removeRule", "allowApp", "denyApp", "allowConn", "denyConn", "importRules",
    "exportRules", "clearLog", "killGroup", "killablePids", "setMode", "setProfileOverride", "addProfile",
    "removeProfile", "toggleProfileNetwork", "setPref", "setListEnabled", "addList", "removeList", "refreshLists",
    "downloadGeoip", "requestStats", "setEnforce", "refreshEnforceStatus", "verifyHelper", "saveProxy", "removeProxy",
    "checkProxy", "setDefaultRoute", "explain", "testExplain",
}
MAX_LINE = 4 * 1024 * 1024


def _peer_uid(writer):
    sock = writer.get_extra_info("socket")
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", creds)[1]
    except OSError:
        return -1


class Server:
    def __init__(self, daemon, path):
        self.d = daemon
        self.path = path
        self.clients = set()
        self.server = None

    async def start(self):
        d = os.path.dirname(self.path)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        if os.path.exists(self.path):
            # a stale socket from a crash, or another daemon still running?
            try:
                r, w = await asyncio.wait_for(asyncio.open_unix_connection(self.path), 1)
                w.close()
                raise SystemExit("citadel-daemon is already running (%s)" % self.path)
            except (OSError, asyncio.TimeoutError):
                os.unlink(self.path)
        old = os.umask(0o177)
        try:
            self.server = await asyncio.start_unix_server(self._client, path=self.path, limit=MAX_LINE)
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)
        self.d._listeners.append(self._broadcast)

    async def stop(self):
        if self.server:
            self.server.close()
        for w in list(self.clients):
            w.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def _write(self, writer, obj):
        if writer.is_closing():
            self.clients.discard(writer)
            return
        try:
            writer.write((json.dumps(obj, separators=(",", ":"), default=str) + "\n").encode())
        except (ConnectionError, RuntimeError):
            self.clients.discard(writer)

    def _broadcast(self, event):
        for w in list(self.clients):
            self._write(w, event)

    async def _client(self, reader, writer):
        if _peer_uid(writer) != os.getuid():
            writer.close()
            return
        self.clients.add(writer)
        self._write(writer, {"type": "state", "full": True, "data": self.d.public()})
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    break
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                self._write(writer, self.handle(msg))
        except ConnectionError:
            pass
        finally:
            self.clients.discard(writer)
            writer.close()

    def handle(self, msg):
        mid = msg.get("id")
        cmd = msg.get("cmd")
        args = msg.get("args") or []
        if cmd == "state":
            return {"type": "reply", "id": mid, "ok": True, "result": self.d.public()}
        if cmd == "status":
            s = self.d.public(["pluginActive", "mode", "activeProfile", "enforce", "enforceActive", "enforceError", "monitorUp",
                               "helperInstalled", "helperVersion", "daemonVersion", "totals", "enforceDrops"])
            s["helperUsable"] = self.d.helperUsable
            s["waiting"] = len(self.d.alerts)
            s["policies"] = len(self.d.rules)
            return {"type": "reply", "id": mid, "ok": True, "result": s}
        if cmd not in COMMANDS or not isinstance(args, list):
            return {"type": "reply", "id": mid, "ok": False, "error": "unknown command %r" % cmd}
        if self.d.pluginActive:
            return {"type": "reply", "id": mid, "ok": False, "paused": True,
                    "error": "The Citadel Omarchy plugin is active, so this service is paused. "
                             "Remove Citadel from the Omarchy bar to use it here."}
        try:
            result = getattr(self.d, cmd)(*args)
        except TypeError as e:
            return {"type": "reply", "id": mid, "ok": False, "error": "bad arguments: %s" % e}
        except Exception as e:                      # keep the daemon up whatever a client sends
            log.exception("command %s failed", cmd)
            return {"type": "reply", "id": mid, "ok": False, "error": str(e)[:300]}
        return {"type": "reply", "id": mid, "ok": True, "result": result}
