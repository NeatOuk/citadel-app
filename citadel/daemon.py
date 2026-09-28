"""citadel-daemon: Citadel's core as a background user service.

A port of the Omarchy plugin's Service.qml. It streams the monitor, decides
every connection (citadel.model, identical to the plugin's Model.js), queues
gate requests, persists state.json, drives the root helper through pkexec, and
runs the proxy and Explain helpers. Front-ends (the Qt app, later the Omarchy
plugin) connect over a Unix socket; see citadel.api.

Only the standard library is used.
"""
import asyncio
import copy
import grp
import json
import logging
import os
import pwd
import re
import shutil
import signal
import sys
import time

from . import model as M
from . import platform as P

log = logging.getLogger("citadel")

VERSION = "0.1.0"
MIN_HELPER = "1.1.1"            # 1.1.1 fixed kill requests that could close other users' sockets
MIN_PROXY_HELPER = "1.3.0"      # proxy routing (nat redirect)

DEFAULT_LISTS = [
    {"id": "firehol1", "name": "FireHOL Level 1 (attacks, malware)", "kind": "ip",
     "url": "https://iplists.firehol.org/files/firehol_level1.netset", "enabled": False},
    {"id": "spamhaus-drop", "name": "Spamhaus DROP (hijacked networks)", "kind": "ip",
     "url": "https://www.spamhaus.org/drop/drop.txt", "enabled": False},
    {"id": "stevenblack", "name": "StevenBlack hosts (ads, malware)", "kind": "domain",
     "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "enabled": False},
    {"id": "hagezi-light", "name": "HaGeZi Light (trackers)", "kind": "domain",
     "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt", "enabled": False},
]
DEFAULT_PREFS = {"interval": 2, "alertTimeout": 90, "alertDefault": "allow", "retentionDays": 30, "notify": True,
                 "modeMinutes": 0, "catchShort": True, "explainCommand": "", "explainModel": "", "explainAgent": ""}

# Session pieces that must never be killed from Citadel, on any desktop.
PROTECTED_NAMES = [
    "quickshell", "qs", "Hyprland", "hyprland", "systemd", "uwsm", "dbus-broker", "dbus-broker-launch", "dbus-daemon",
    "pipewire", "pipewire-pulse", "wireplumber", "Xwayland", "Xorg", "xdg-desktop-portal", "xdg-desktop-portal-hyprland",
    "xdg-desktop-portal-gnome", "xdg-desktop-portal-kde", "xdg-desktop-portal-gtk", "xdg-desktop-portal-wlr",
    "gnome-keyring-daemon", "gnome-shell", "gnome-session-binary", "mutter", "gsd-xsettings", "plasmashell",
    "kwin_wayland", "kwin_x11", "ksmserver", "kded6", "kded5", "sway", "swaybg", "waybar", "niri", "labwc", "river",
    "cosmic-comp", "cosmic-session", "xfce4-session", "xfwm4", "cinnamon", "mate-session", "lxqt-session",
    "sddm", "gdm", "lightdm", "citadel-daemon", "citadel-app", "polkit-kde-authentication-agent-1", "polkitd",
]
INTERPRETER = re.compile(r"^(python|node|perl|ruby|bash|sh|dash|zsh|fish|lua|luajit|deno|bun|php)[0-9.]*$")

# state keys sent to front-ends (the names the plugin's views read on `s`)
PUBLIC = ["rules", "profiles", "profileOverride", "mode", "silentUntil", "enforce", "lists", "decisionLog", "prefs",
          "conns", "apps", "network", "decisions", "groups", "alerts", "stats", "listStatus", "ipCidrCount", "geoip",
          "approx", "protectedPids", "recentShort", "kernelLog", "helperVersion", "helperLogging", "learned", "rate",
          "totals", "monitorError", "monitorUp", "ticks", "now", "activeProfile", "inWheel", "helperInstalled",
          "enforceActive", "enforceBusy", "enforceError", "enforceAppliedAt", "enforceDrops", "proxies", "defaultRoute",
          "proxyStatus", "proxyLog", "proxyCarried", "proxyCheck", "proxyError", "explanations", "explainTestResult",
          "defaultAgent", "installedAgents", "uid", "session", "resolved", "daemonVersion", "privilegedGroup",
          "pluginActive"]


def _now():
    return time.time()


class Paths:
    def __init__(self):
        home = os.path.expanduser("~")
        self.state_dir = os.environ.get("CITADEL_STATE_DIR") or os.path.join(home, ".local/share/citadel")
        self.state = os.path.join(self.state_dir, "state.json")
        self.spec = os.path.join(self.state_dir, "enforce", "spec.json")
        self.kill = os.path.join(self.state_dir, "enforce", "kill.json")
        self.runtime_dir = os.environ.get("CITADEL_RUNTIME_DIR") or os.path.join(P.runtime_base(), "citadel")
        self.socket = os.path.join(self.runtime_dir, "daemon.sock")
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [os.environ.get("CITADEL_LIBEXEC"), os.path.join(here, "libexec"), "/usr/lib/citadel/libexec"]
        self.libexec = next((c for c in candidates if c and os.path.exists(os.path.join(c, "citadel-monitor"))), candidates[-1])
        # another OS can bring its own monitor with the same JSON protocol
        self.monitor = os.environ.get("CITADEL_MONITOR") or os.path.join(self.libexec, "citadel-monitor")
        self.proxy = os.path.join(self.libexec, "citadel-proxy")
        self.explain = os.path.join(self.libexec, "citadel-explain")
        self.helper = os.environ.get("CITADEL_HELPER") or "/usr/lib/citadel/citadel-enforcer"
        self.pkexec = os.environ.get("CITADEL_PKEXEC", "pkexec")      # "" in tests: run the helper directly
        self.agent_file = os.environ.get("CITADEL_AGENT_FILE") or os.path.join(home, ".config/omarchy/defaults/agent")
        # macOS: the host app (Citadel.app) plays citadel-helper's part, over a socket
        self.host_socket = os.environ.get("CITADEL_HOST_SOCKET") or os.path.join(self.runtime_dir, "host.sock")
        transport = os.environ.get("CITADEL_HELPER_TRANSPORT", "")      # "host" | "pkexec" | "" (the OS default)
        self.use_host = transport == "host" or (sys.platform == "darwin" and transport != "pkexec")


class Daemon:
    def __init__(self, paths=None):
        self.p = paths or Paths()
        # persisted
        self.rules, self.profiles, self.profileOverride = [], [{"name": "Default", "networks": []}], ""
        self.mode, self.silentUntil, self.enforce = "guarded", 0, False
        self.lists, self.decisionLog, self.prefs = [], [], dict(DEFAULT_PREFS)
        self.proxies, self.defaultRoute = [], "direct"
        # live
        self.conns, self.apps, self.network = [], {}, {"names": [], "ssid": ""}
        self.decisions, self.groups, self.alerts, self.session, self.resolved = {}, [], [], {}, {}
        self.stats = {"series": [], "topAppsToday": [], "topHostsToday": [], "countriesToday": [], "topApps7d": []}
        self.listStatus, self.ipCidrs, self.geoip, self.approx = {}, [], {"installed": False, "error": ""}, {}
        self.protectedPids, self.recentShort, self.kernelLog = {}, [], {"running": False, "error": "", "seen": 0}
        self.helperVersion, self.helperLogging, self.learned = "", False, {}
        self.rate, self.totals = {"up": 0, "down": 0}, {"connections": 0, "apps": 0, "denied": 0}
        self.monitorError, self.monitorUp, self.ticks, self.now, self.uid = "", False, 0, _now(), -1
        self.inWheel, self.privilegedGroup = True, "wheel"
        self.helperInstalled, self.enforceActive, self.enforceBusy = False, False, False
        self.enforceError, self.enforceAppliedAt, self.enforceDrops = "", 0, 0
        self.proxyStatus, self.proxyLog, self.proxyCarried, self.proxyCheck, self.proxyError = {}, [], [], {}, ""
        self._proxyFailed = {}
        self.explanations, self.explainTestResult = {}, {}
        self.defaultAgent, self.installedAgents = "", []
        self.daemonVersion = VERSION
        # The Citadel Omarchy plugin runs its own core. While it is active this
        # daemon pauses entirely (no monitor, no firewall, no state writes), so
        # the two never fight over the firewall table or state.json.
        self.pluginActive = False
        self._besidePlugin = os.environ.get("CITADEL_ALLOW_BESIDE_PLUGIN") == "1"   # dev: own dirs, watch-only
        self._pluginMarker = os.environ.get("CITADEL_PLUGIN_MARKER") or "citadel-monitor"
        self.loaded = False
        # internals
        self._lastSpec, self._appliedRoutes, self._pendingRoutes = "", None, None
        self._forceSync, self._lastSyncAt, self._syncHandle = False, 0, None
        self._jobs = asyncio.Queue()
        self._explainQueue = asyncio.Queue()
        self._monitor = self._proxy = None
        self._dirty = set()
        self._listeners = []            # callables(event dict)
        self._saveHandle = None
        self._helperStamp = ""
        self._notifications = {}        # alert key -> notify process
        self._tasks = []
        from .platform.hostbridge import HostBridge
        self.bridge = HostBridge(self.p.host_socket) if self.p.use_host else None

    # ------------------------------------------------------------ derived
    @property
    def activeProfile(self):
        return M.active_profile(self.profiles, self.profileOverride, self.network.get("names") or [])

    @property
    def ipCidrCount(self):
        return len(self.ipCidrs)

    @property
    def helperGate(self):
        return M.helper_gate(self.helperInstalled, self.helperVersion, MIN_HELPER)

    @property
    def helperUsable(self):
        return self.helperGate["usable"]

    @property
    def helperOutdated(self):
        return self.helperGate["reason"] == "outdated"

    @property
    def helperProblem(self):
        if not self.helperOutdated:
            return ""
        return ("is older than " + MIN_HELPER if M.version_less(self.helperVersion, MIN_HELPER)
                else "is an unreleased build") + " and has a security bug"

    @property
    def proxyCapable(self):
        return self.helperUsable and not M.version_less(self.helperVersion, MIN_PROXY_HELPER)

    def public(self, keys=None):
        out = {}
        for k in keys or PUBLIC:
            out[k] = getattr(self, k)
        if keys is not None:
            return out
        out.update({"helperUsable": self.helperUsable, "helperOutdated": self.helperOutdated,
                    "helperProblem": self.helperProblem, "proxyCapable": self.proxyCapable,
                    "minHelper": MIN_HELPER, "minProxyHelper": MIN_PROXY_HELPER, "defaultLists": DEFAULT_LISTS})
        return out

    # ------------------------------------------------------------ events to clients
    def changed(self, *names):
        self._dirty.update(names)

    def emit(self, event):
        for fn in list(self._listeners):
            try:
                fn(event)
            except Exception:                              # a broken client must not stop the daemon
                log.exception("listener failed")

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(0.1)
            if self._dirty:
                keys = sorted(k for k in self._dirty if k in PUBLIC)
                self._dirty.clear()
                self.emit({"type": "state", "data": self.public(keys)})

    # ------------------------------------------------------------ persistence
    def _load(self):
        s = {}
        try:
            with open(self.p.state) as f:
                s = json.load(f)
        except (OSError, ValueError):
            s = {}
        if s.get("version") == 2:
            self.rules = [M.make_rule(r) for r in s.get("rules") or []]
            self.profiles = s.get("profiles") or [{"name": "Default", "networks": []}]
            self.profileOverride = s.get("profileOverride") or ""
            legacy = {"prompt": "guarded", "silentAllow": "open", "silentDeny": "lockdown"}
            m = legacy.get(s.get("mode"), s.get("mode"))
            self.mode = m if m in ("guarded", "open", "lockdown") else "guarded"
            self.silentUntil = float(s.get("silentUntil") or 0)
            self.enforce = bool(s.get("enforce"))
            self.decisionLog = s.get("decisionLog") or []
            self.prefs = dict(DEFAULT_PREFS, **(s.get("prefs") or {}))
            self.proxies = [x for x in s.get("proxies") or [] if x and x.get("id") and x.get("listen")]
            self.defaultRoute = s.get("defaultRoute") or "direct"
        saved = {l["id"]: l for l in s.get("lists") or [] if isinstance(l, dict) and "id" in l}
        merged = [dict(d, **saved.get(d["id"], {})) for d in DEFAULT_LISTS]
        merged += [l for l in s.get("lists") or [] if isinstance(l, dict) and l.get("id") not in {d["id"] for d in DEFAULT_LISTS}]
        self.lists = merged
        self.loaded = True
        self.changed(*PUBLIC)
        self.save()

    def save(self):
        if not self.loaded or self.pluginActive:
            return
        if self._saveHandle:
            self._saveHandle.cancel()
        self._saveHandle = asyncio.get_running_loop().call_later(0.3, self._write_state)

    def _state_text(self):
        return json.dumps({"version": 2, "rules": self.rules, "profiles": self.profiles, "profileOverride": self.profileOverride,
                           "mode": self.mode, "silentUntil": self.silentUntil, "enforce": self.enforce, "lists": self.lists,
                           "decisionLog": self.decisionLog[:300], "prefs": self.prefs, "proxies": self.proxies,
                           "defaultRoute": self.defaultRoute}, indent=2) + "\n"

    def _write_state(self):
        self._saveHandle = None
        P.write_atomic(self.p.state, self._state_text())

    # ------------------------------------------------------------ monitor
    async def _run_monitor(self):
        while True:
            if self.pluginActive:
                await asyncio.sleep(1)
                continue
            env = dict(os.environ, CITADEL_STATE_DIR=self.p.state_dir)
            try:
                self._monitor = await asyncio.create_subprocess_exec(
                    sys.executable, self.p.monitor, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, env=env, limit=64 * 1024 * 1024)
            except OSError as e:
                self.monitorUp, self.monitorError = False, "monitor could not start: %s" % e
                self.changed("monitorUp", "monitorError")
                await asyncio.sleep(3)
                continue
            self.monitorUp, self.monitorError = True, ""
            self.changed("monitorUp", "monitorError")
            self._send_config()
            err_task = asyncio.create_task(self._monitor.stderr.read())
            while True:
                line = await self._monitor.stdout.readline()
                if not line:
                    break
                try:
                    self._on_monitor_line(json.loads(line))
                except ValueError:
                    continue
                except Exception:
                    log.exception("monitor line failed")
            code = await self._monitor.wait()
            err = (await err_task).decode(errors="replace")[-300:]
            self.monitorUp = False
            self.monitorError = "monitor stopped (exit %s) %s" % (code, err)
            self.changed("monitorUp", "monitorError")
            await asyncio.sleep(3)

    def _send(self, obj):
        m = self._monitor
        if m and m.returncode is None and m.stdin:
            m.stdin.write((json.dumps(obj) + "\n").encode())

    def _send_config(self):
        if not self.loaded:
            return
        hosts = {}
        for r in self.rules:
            if r["host"] != "*" and not M.is_address_like(r["host"]):
                hosts[r["host"]] = True
        for x in self.proxies:
            if not M.is_address_like(x["host"]):
                hosts[M.norm_host(x["host"])] = True
        self._send({"cmd": "config", "interval": float(self.prefs.get("interval") or 2),
                    "retentionDays": float(self.prefs.get("retentionDays") or 30),
                    "resolveHosts": list(hosts), "lists": self.lists})

    def _on_monitor_line(self, m):
        t = m.get("type")
        if t == "tick":
            self._on_tick(m)
        elif t == "stats":
            self.stats = m
            self.changed("stats")
        elif t == "resolved":
            self.resolved = m.get("hosts") or {}
            self.changed("resolved")
            self._reevaluate()
        elif t == "lists":
            self.listStatus = {l["id"]: l for l in m.get("lists") or []}
            self.ipCidrs = m.get("ipCidrs") or []
            self.changed("listStatus", "ipCidrCount")
            self._reevaluate()
        elif t == "geoip":
            self.geoip = m
            self.changed("geoip")
        elif t == "log":
            log.warning("monitor: %s", m.get("msg"))

    def _ctx(self):
        alive = {}
        for info in self.apps.values():
            for pid in info.get("pids") or []:
                alive[str(pid)] = True
        return {"profile": self.activeProfile, "mode": self.mode, "resolved": self.resolved, "alivePids": alive,
                "session": self.session, "learned": M.learned_ips(self.learned), "learnedCg": M.learned_cgroups(self.learned)}

    def _on_tick(self, m):
        self.now = m.get("ts") or _now()
        if m.get("uid") is not None:
            self.uid = m["uid"]
        if m.get("selfPid"):
            self.protectedPids = {str(m["selfPid"]): True, str(os.getpid()): True}
        self.conns = m.get("conns") or []
        self.apps = m.get("apps") or {}
        self.network = m.get("network") or {"names": [], "ssid": ""}
        if m.get("kernelLog"):
            self.kernelLog = m["kernelLog"]
        first = self.ticks == 0
        self.ticks += 1
        self._prune_expired_rules()
        self.learned = M.learn_targets(self.learned, self.rules, self.conns, self.now, 3600)
        ctx = self._ctx()
        dec, up, down, denied = {}, 0, 0, 0
        new_alerts = list(self.alerts)
        logged = []
        for c in self.conns:
            if self._is_own(c):
                # Citadel's proxy tunnels carry traffic that was already decided
                dec[c["key"]] = {"verdict": "allow", "source": "citadel", "rule": None}
                continue
            d = M.decide(c, self.rules, ctx)
            if d["source"] == "rule" and d["verdict"] == "allow" and d["rule"].get("exeHash") and c.get("exe") and self.apps.get(c["exe"]):
                h = (self.apps[c["exe"]].get("trust") or {}).get("hash")
                if h and h != d["rule"]["exeHash"]:
                    d = {"verdict": "prompt", "source": "changed", "rule": d["rule"]}
            dec[c["key"]] = d
            up += c.get("upRate") or 0
            down += c.get("downRate") or 0
            if d["verdict"] == "deny":
                denied += 1
            if not first and c.get("new"):
                if d["verdict"] == "prompt":
                    self._queue_alert(new_alerts, c, d)
                elif d["source"] in ("silent", "blocklist"):
                    logged.append(self._log_entry(c, d["verdict"], self._silent_source(c, d)))
        self.decisions = dec
        self.groups = M.group_by_app(self.conns, dec)
        self.rate = {"up": up, "down": down}
        self.totals = {"connections": len(self.conns), "apps": len(self.groups), "denied": denied}
        shorts = m.get("short") or []
        if shorts:
            recent = []
            for sc in shorts:
                if self._is_own(sc):
                    continue
                sd = M.decide(sc, self.rules, ctx)
                recent.append({"conn": sc, "decision": sd})
                if first:
                    continue
                if self._proxyFailed.get("%s|%s" % (sc.get("raddr"), sc.get("rport")), 0) > self.now - 10:
                    continue
                trusted = sc.get("confidence") in ("matched", "likely")
                if sd["verdict"] == "prompt" and trusted:
                    self._queue_alert(new_alerts, sc, sd)
                elif sd["source"] in ("silent", "blocklist"):
                    logged.append(self._log_entry(sc, sd["verdict"], self._silent_source(sc, sd)))
            merged = list(self.recentShort)
            for item in reversed(recent):
                c = item["conn"]
                for i, o in enumerate(merged):
                    oc = o["conn"]
                    if (oc.get("exe") == c.get("exe") and (oc.get("viaId") or "") == (c.get("viaId") or "")
                            and oc.get("raddr") == c.get("raddr") and oc.get("rport") == c.get("rport")
                            and c.get("ts", 0) - oc.get("ts", 0) < 60):
                        merged.pop(i)
                        merged.insert(0, {"conn": c, "decision": item["decision"], "count": (o.get("count") or 1) + 1})
                        break
                else:
                    merged.insert(0, {"conn": c, "decision": item["decision"], "count": 1})
            self.recentShort = merged[:60]
        if len(new_alerts) != len(self.alerts):
            self.alerts = new_alerts
        if logged:
            self._log(logged)
        self.changed("now", "uid", "protectedPids", "conns", "apps", "network", "kernelLog", "ticks", "learned",
                     "decisions", "groups", "rate", "totals", "recentShort", "alerts", "activeProfile")
        if self.enforce:
            self._sync_enforcement(first)

    def _is_own(self, c):
        """A connection of Citadel's own proxy process (its upstream tunnels)."""
        return c.get("app") == "Citadel proxy" or bool(re.search(r"/citadel-proxy(\s|$)", c.get("cmd") or ""))

    def _silent_source(self, c, d):
        if d["source"] == "blocklist":
            return "feed " + (c.get("list") or "")
        return "open mode" if self.mode == "open" else "lockdown"

    # ------------------------------------------------------------ alerts
    def _queue_alert(self, queue, conn, d):
        key = M.alert_key(conn)
        if any(a["key"] == key for a in queue):
            return
        info = self.apps.get(conn.get("exe")) if conn.get("exe") else None
        alert = {"key": key, "conn": conn, "firstSeen": self.now, "changed": d["source"] == "changed",
                 "short": bool(conn.get("short")), "trust": info.get("trust") if info else {"level": "unknown"},
                 "hasOwnScope": bool(info and info.get("owned"))}
        queue.append(alert)
        if self.prefs.get("notify") is not False:
            asyncio.get_running_loop().create_task(self._notify(alert))

    def answer(self, key, action, scope="host", duration="forever", source="", viaScoped=False, route=None):
        alert = next((a for a in self.alerts if a["key"] == key), None)
        if not alert:
            return False
        if duration == "once":
            self.session = dict(self.session, **{key: action})
            self.changed("session")
        else:
            info = self.apps.get(alert["conn"].get("exe"))
            if alert.get("changed"):
                self.rules = [r for r in self.rules if not (r["app"] == alert["conn"].get("exe") and r.get("exeHash"))]
            self.addRule(M.rule_from_alert(alert, action, scope, duration, "*", info, viaScoped is True, route), True)
        if action == "deny":
            c0 = alert["conn"]

            def pred(c):
                if c.get("exe") != c0.get("exe"):
                    return False
                if viaScoped is True and (c.get("viaId") or "") != (c0.get("viaId") or ""):
                    return False
                if scope == "app":
                    return True
                if scope == "hostPort" and c.get("rport") != c0.get("rport"):
                    return False
                return c.get("raddr") == c0.get("raddr") or bool(c0.get("host") and c.get("host") == c0.get("host"))
            self._kill(M.kill_targets(self.conns, pred, self.uid))
        src = source or ("you · once" if duration == "once" else "you · until quit" if duration == "untilQuit" else "you · from now on")
        self._log([self._log_entry(alert["conn"], action, src)])
        self.alerts = [a for a in self.alerts if a["key"] != key]
        self.changed("alerts")
        self._close_notification(key)
        self._resolve(alert.get("flows") or [], action == "allow")
        self._reevaluate()
        return True

    async def _clock_loop(self):
        while True:
            await asyncio.sleep(1)
            self.now = _now()
            if self.silentUntil > 0 and self.now >= self.silentUntil:
                self.setMode("guarded", 0)
            limit = float(self.prefs.get("alertTimeout") or 0)
            if limit > 0:
                for a in [a for a in self.alerts if self.now - a["firstSeen"] > limit]:
                    self.answer(a["key"], "deny" if self.prefs.get("alertDefault") == "deny" else "allow",
                                "hostPort", "once", "timeout")
            self.changed("now")

    # ------------------------------------------------------------ notifications
    async def _notify(self, alert):
        """A desktop notification for a gate request; its buttons answer it."""
        c = alert["conn"]
        title = "Changed app at the gate" if alert.get("changed") else "At the gate"
        body = "%s → %s:%s" % (_app_with_origin(c), c.get("host") or c.get("raddr") or "?", c.get("rport"))
        if self.bridge and self.helperInstalled:
            # macOS: the host app posts it with buttons (UNUserNotificationCenter)
            self._run(["notify", json.dumps({"key": alert["key"], "title": title, "body": body})])
            return
        actions = [("once", "Allow once"), ("always", "Always allow"), ("block", "Block"), ("default", "Open Citadel")]
        proc = await P.notify(title, body, actions)
        if not proc:
            return
        self._notifications[alert["key"]] = proc
        try:
            out = (await proc.stdout.read()).decode(errors="replace").split()
        finally:
            self._notifications.pop(alert["key"], None)
        act = out[-1] if out else ""
        if act == "once":
            self.answer(alert["key"], "allow", "hostPort", "once", "you · once (notification)")
        elif act == "always":
            self.answer(alert["key"], "allow", "host", "forever", "you · from now on (notification)")
        elif act == "block":
            self.answer(alert["key"], "deny", "host", "forever", "you · blocked (notification)")
        elif act == "default":
            self.emit({"type": "open", "view": "gate"})
            if not self._listeners:
                P.launch_app(["--gate"])

    def _close_notification(self, key):
        if self.bridge and self.helperInstalled:
            self._run(["notify", json.dumps({"key": key, "remove": True})])
        proc = self._notifications.pop(key, None)
        if proc and proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass

    # ------------------------------------------------------------ decision log
    def _log_entry(self, conn, verdict, source):
        return {"ts": self.now, "app": _app_with_origin(conn), "exe": conn.get("exe") or "", "via": conn.get("viaId") or "",
                "dest": conn.get("host") or conn.get("raddr") or "?", "ip": conn.get("raddr"), "port": conn.get("rport"),
                "cc": conn.get("cc") or "", "verdict": verdict, "source": source}

    def _log(self, entries):
        self.decisionLog = (entries + self.decisionLog)[:300]
        self.changed("decisionLog")
        self.save()

    def clearLog(self):
        self.decisionLog = []
        self.changed("decisionLog")
        self.save()

    # ------------------------------------------------------------ rules
    def addRule(self, rule, fromAlert=False):
        r = M.make_rule(rule)
        self.rules = [x for x in self.rules if not (x["profile"] == r["profile"] and x["app"] == r["app"]
                                                   and (x.get("via") or "*") == r["via"] and x["host"] == r["host"]
                                                   and x["port"] == r["port"])] + [r]
        if not fromAlert and r["action"] == "deny":
            ctx = self._ctx()
            self._kill(M.kill_targets(self.conns, lambda c: M.rule_matches(r, c, ctx), self.uid))
        self._rules_changed()
        return r

    def updateRule(self, id, fields):
        self.rules = [M.make_rule(dict(r, **fields, id=id)) if r["id"] == id else r for r in self.rules]
        self._rules_changed()

    def removeRule(self, id):
        self.rules = [r for r in self.rules if r["id"] != id]
        self._rules_changed()

    def _rules_changed(self):
        self.changed("rules")
        self.save()
        self._send_config()
        self._reevaluate()
        if self.enforce:
            self._sync_enforcement(True)

    def _prune_expired_rules(self):
        ctx = self._ctx()
        keep = [r for r in self.rules if r["duration"] != "untilQuit" or M.rule_active(r, dict(ctx, profile=r["profile"]))]
        if len(keep) != len(self.rules):
            self.rules = keep
            self.changed("rules")
            self.save()

    def allowApp(self, exe, viaId=None):
        return self.addRule({"app": exe, "via": viaId or "*", "action": "allow"})

    def denyApp(self, exe, viaId=None):
        return self.addRule({"app": exe, "via": viaId or "*", "action": "deny"})

    def denyConn(self, conn):
        return self.addRule({"app": conn.get("exe") or "*", "via": conn.get("viaId") or "*",
                             "host": conn.get("host") or conn.get("raddr"), "action": "deny"})

    def allowConn(self, conn):
        return self.addRule({"app": conn.get("exe") or "*", "via": conn.get("viaId") or "*",
                             "host": conn.get("host") or conn.get("raddr"), "action": "allow"})

    def importRules(self, text):
        try:
            p = json.loads(text)
        except ValueError:
            return "not valid JSON"
        items = p if isinstance(p, list) else (p.get("rules") if isinstance(p, dict) else None)
        if not isinstance(items, list):
            return "no rules found"
        fresh = [M.make_rule(r) for r in items if isinstance(r, dict)]
        keys = {(r["profile"], r["app"], r["via"], r["host"], r["port"]) for r in fresh}
        self.rules = [x for x in self.rules
                      if (x["profile"], x["app"], x.get("via") or "*", x["host"], x["port"]) not in keys] + fresh
        self._rules_changed()                      # one save, one config, one firewall update
        return ""

    def importFeed(self, name, domains, url=""):
        """A big imported domain list as a feed: a subscription when it came
        from a URL, else a local list file in the feeds folder."""
        if url:
            return self.addList(name, url, "domain")
        clean = sorted({d for d in (str(x).strip().lower() for x in domains or []) if re.match(r"^[a-z0-9_.:-]+$", d)})
        if not clean:
            return ""
        lid = "import-" + M._new_id()[:10]
        P.write_atomic(os.path.join(self.p.state_dir, "lists", lid + ".txt"), "\n".join(clean) + "\n", 0o644)
        self.lists = self.lists + [{"id": lid, "name": str(name or "Imported list")[:120], "url": "", "local": True,
                                    "kind": "domain", "enabled": True}]
        self.changed("lists")
        self.save()
        self._send_config()
        return lid

    def exportRules(self):
        return json.dumps({"version": 2, "rules": self.rules}, indent=2)

    def _reevaluate(self):
        ctx = self._ctx()
        dec, denied = {}, 0
        for c in self.conns:
            d = {"verdict": "allow", "source": "citadel", "rule": None} if self._is_own(c) else M.decide(c, self.rules, ctx)
            dec[c["key"]] = d
            if d["verdict"] == "deny":
                denied += 1
        self.decisions = dec
        self.groups = M.group_by_app(self.conns, dec)
        self.totals = {"connections": len(self.conns), "apps": len(self.groups), "denied": denied}
        still = [a for a in self.alerts if not self._is_own(a["conn"])
                 and (M.decide(a["conn"], self.rules, ctx)["verdict"] == "prompt" or a.get("changed"))]
        for a in self.alerts:
            if a not in still:
                self._close_notification(a["key"])
                if a.get("flows"):                     # answered by a new policy or the mode
                    self._resolve(a["flows"], M.decide(a["conn"], self.rules, ctx)["verdict"] == "allow")
        self.alerts = still
        self.changed("decisions", "groups", "totals", "alerts", "activeProfile")
        if self.enforce:
            self._sync_enforcement(False)

    # ------------------------------------------------------------ kill (own processes only)
    def _is_protected_cmd(self, cmd):
        first = " ".join(str(cmd or "").split(" ")[:3])
        return any(re.search(r"(^|[/\s])" + re.escape(n) + r"(\s|$)", first) for n in PROTECTED_NAMES)

    def killablePids(self, group):
        if not group or group.get("system") or not group.get("exe"):
            return []
        name = group["exe"].split("/")[-1]
        if name in PROTECTED_NAMES:
            return []
        pids = []
        if group.get("viaId") or INTERPRETER.match(name):
            pids = [c.get("pid") for c in group.get("conns") or [] if c.get("pid") and not self._is_protected_cmd(c.get("cmd"))]
        else:
            pids = list((self.apps.get(group["exe"]) or {}).get("pids") or [])
        seen, out = set(), []
        for p in pids:
            if not p or p in seen or self.protectedPids.get(str(p)):
                continue
            seen.add(p)
            out.append(p)
        return out

    def killGroup(self, group, force=False):
        pids = self.killablePids(group)
        uid = os.getuid()
        killed = 0
        for pid in pids:
            try:
                if P.process_uid(pid) != uid:                  # never another user's process
                    continue
                os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
                killed += 1
            except (OSError, ValueError):
                continue
        if killed:
            c = (group.get("conns") or [{"app": group.get("app"), "exe": group.get("exe")}])[0]
            self._log([{"ts": self.now, "app": _app_with_origin(c), "exe": group.get("exe"), "via": group.get("viaId") or "",
                        "dest": "%d process(es)" % killed, "ip": "", "port": "", "cc": "", "verdict": "deny",
                        "source": "force-killed by you" if force else "killed by you"}])
        return killed

    # ------------------------------------------------------------ modes, zones, prefs
    def setMode(self, m, minutes=0):
        self.mode = m if m in ("guarded", "open", "lockdown") else "guarded"
        self.silentUntil = _now() + float(minutes) * 60 if self.mode != "guarded" and minutes and float(minutes) > 0 else 0
        self.changed("mode", "silentUntil")
        self.save()
        self._reevaluate()
        if self.enforce:
            self._sync_enforcement(True)

    def setProfileOverride(self, name):
        self.profileOverride = name or ""
        self.changed("profileOverride", "activeProfile")
        self.save()
        self._reevaluate()
        if self.enforce:
            self._sync_enforcement(True)

    def addProfile(self, name):
        name = str(name or "").strip()
        if not name or any(p["name"] == name for p in self.profiles):
            return
        self.profiles = self.profiles + [{"name": name, "networks": []}]
        self.changed("profiles")
        self.save()

    def removeProfile(self, name):
        if len(self.profiles) <= 1:
            return
        self.profiles = [p for p in self.profiles if p["name"] != name]
        self.rules = [r for r in self.rules if r["profile"] != name]
        if self.profileOverride == name:
            self.profileOverride = ""
        self.changed("profiles", "rules", "profileOverride")
        self.save()
        self._reevaluate()

    def toggleProfileNetwork(self, name, net):
        out = []
        for p in self.profiles:
            nets = [n for n in p.get("networks") or [] if n != net] if p["name"] != name else list(p.get("networks") or [])
            if p["name"] == name:
                if net in nets:
                    nets.remove(net)
                else:
                    nets.append(net)
            out.append({"name": p["name"], "networks": nets})
        self.profiles = out
        self.changed("profiles", "activeProfile")
        self.save()
        self._reevaluate()

    def setPref(self, key, value):
        if key not in DEFAULT_PREFS:
            return
        self.prefs = dict(self.prefs, **{key: value})
        self.changed("prefs")
        self.save()
        if key in ("interval", "retentionDays"):
            self._send_config()
        if key == "catchShort" and self.enforce:
            self._sync_enforcement(True)
        if key in ("explainAgent", "explainCommand"):
            self.changed("defaultAgent")

    # ------------------------------------------------------------ feeds, geoip, stats
    def setListEnabled(self, id, on):
        self.lists = [dict(l, enabled=bool(on)) if l["id"] == id else l for l in self.lists]
        self.changed("lists")
        self.save()
        self._send_config()

    def addList(self, name, url, kind):
        url = str(url or "").strip()
        if not re.match(r"^https?://", url):
            return
        lid = "custom-" + M._new_id()[:8]
        self.lists = self.lists + [{"id": lid, "name": name or url, "url": url, "kind": "ip" if kind == "ip" else "domain", "enabled": True}]
        self.changed("lists")
        self.save()
        self._send_config()

    def removeList(self, id):
        gone = [l for l in self.lists if l["id"] == id and l.get("local")]
        for l in gone:                                   # an imported list's file goes too
            try:
                os.unlink(os.path.join(self.p.state_dir, "lists", re.sub(r"[^A-Za-z0-9_.-]", "_", l["id"]) + ".txt"))
            except OSError:
                pass
        self.lists = [l for l in self.lists if l["id"] != id or any(d["id"] == id for d in DEFAULT_LISTS)]
        self.changed("lists")
        self.save()
        self._send_config()

    def refreshLists(self):
        self._send({"cmd": "refreshLists"})

    def downloadGeoip(self):
        self.geoip = dict(self.geoip, downloading=True)
        self.changed("geoip")
        self._send({"cmd": "geoipDownload"})

    def requestStats(self):
        self._send({"cmd": "stats"})

    # ------------------------------------------------------------ helper
    async def _helper_watch(self):
        """Notice the helper being installed, upgraded or removed; verify its version."""
        n = 0
        while True:
            installed = self.bridge.available() if self.bridge else os.access(self.p.helper, os.X_OK)
            if installed != self.helperInstalled:
                self.helperInstalled = installed
                if not installed:
                    self.helperVersion = ""
                self.changed("helperInstalled", "helperVersion")
                if installed:
                    self.verifyHelper()
            if installed and not self.bridge:
                try:
                    st = os.stat(self.p.helper)
                    stamp = "%d %d" % (st.st_mtime, st.st_size)
                except OSError:
                    stamp = ""
                if self._helperStamp and stamp and stamp != self._helperStamp:
                    self.verifyHelper()
                self._helperStamp = stamp
                if self.helperOutdated and n % 4 == 0:
                    self.verifyHelper()
            n += 1
            await asyncio.sleep(15 if installed else 10)

    def verifyHelper(self):
        if not self.helperInstalled:
            return

        def done(code, out, err):
            try:
                s = json.loads(out)
            except ValueError:
                s = {}
            self.helperVersion = (s.get("version") or "1.1.0") if code == 0 else ""
            if code == 0 and self.bridge:
                self._feedsSig = None              # a restarted host/extension lost what it had: send again
                self._lastSpec = ""
            if code == 0:
                self.enforceActive = bool(s.get("active"))
                self.enforceDrops = int(s.get("drops") or 0)
                self.helperLogging = bool(s.get("logging"))
            if self.helperOutdated:
                self.enforceError = ("Enforcement paused: citadel-helper %s %s. Update it." % (self.helperVersion, self.helperProblem)
                                     if self.enforce else "")
            elif self.helperUsable:
                if "citadel-helper" in self.enforceError:
                    self.enforceError = ""
                if self.enforce:
                    self._lastSpec = ""
                    self._sync_enforcement(True)
            self.changed("helperVersion", "enforceActive", "enforceDrops", "enforceError", "helperLogging")
        self._run(["status"], done)

    def _run(self, args, done=None):
        # paused beside the plugin: only read-only status, never apply/kill/off
        if self.pluginActive and args[0] != "status":
            if done:
                done(1, "", "paused: the Citadel Omarchy plugin is active")
            return
        # Single choke point for privileged calls: "apply" and "kill" only ever
        # go to a helper whose verified version is >= MIN_HELPER. ("status" and
        # "off" are safe with any helper.)
        if args[0] in ("apply", "kill") and not self.helperUsable:
            if done:
                done(1, "", "refused: citadel-helper %s is not >= %s" % (self.helperVersion or "version unknown", MIN_HELPER))
            return
        self._jobs.put_nowait((args, done))

    async def _helper_loop(self):
        while True:
            args, done = await self._jobs.get()
            if self.bridge:
                code, out, err = await self._host_call(args)
                out, err = out.encode(), err.encode()
            else:
                cmd = ([self.p.pkexec] if self.p.pkexec else []) + [self.p.helper] + list(args)
                try:
                    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    out, err = await proc.communicate()
                    code = proc.returncode
                except OSError as e:
                    code, out, err = 127, b"", str(e).encode()
            if done:
                try:
                    done(code, out.decode(errors="replace"), err.decode(errors="replace"))
                except Exception:
                    log.exception("helper callback failed")

    async def _host_call(self, args):
        """A helper call through the macOS host app: file arguments travel as JSON."""
        from .platform.hostbridge import file_payload
        cmd, rest = args[0], list(args[1:])
        try:
            if cmd in ("apply", "kill") and rest:
                payload = {"spec" if cmd == "apply" else "targets": file_payload(rest[0])}
                if cmd == "apply":
                    # proxy logins travel to the extension in memory only, never in the spec file
                    for px in payload["spec"].get("proxies") or []:
                        cred = P.lookup_secret(px["id"]) if px.get("auth") else None
                        if cred:
                            px["user"], px["password"] = cred
            elif cmd in ("resolve", "feeds", "notify") and rest:
                payload = json.loads(rest[0])
            else:
                payload = {}
        except (OSError, ValueError) as e:
            return 1, "", "bad %s request: %s" % (cmd, e)
        return await self.bridge.request(cmd, payload)

    # ------------------------------------------------------------ the gate on macOS (paused flows)
    def _on_host_event(self, ev):
        """A new connection the network extension paused until the gate answers,
        or a button pressed on one of the host's notifications."""
        if ev.get("type") == "answer" and not self.pluginActive:
            key, choice = str(ev.get("key") or ""), ev.get("choice")
            if choice == "once":
                self.answer(key, "allow", "hostPort", "once", "you · once (notification)")
            elif choice == "always":
                self.answer(key, "allow", "host", "forever", "you · from now on (notification)")
            elif choice == "block":
                self.answer(key, "deny", "host", "forever", "you · blocked (notification)")
            elif choice == "open":
                self.emit({"type": "open", "view": "gate"})
                if not self._listeners:
                    P.launch_app(["--gate"])
            return
        if ev.get("type") in ("error", "stats") and not self.pluginActive:
            self._on_proxy_line(ev)               # proxy routing in the extension reports like citadel-proxy
            return
        if ev.get("type") != "flow" or not ev.get("id") or self.pluginActive:
            return
        import ipaddress
        raddr = str(ev.get("raddr") or "")
        try:
            a = ipaddress.ip_address(raddr)
            scope = "loopback" if a.is_loopback else "lan" if a.is_private or a.is_link_local else "internet"
        except ValueError:
            scope = "other"
        exe = str(ev.get("exe") or "")
        conn = {"key": "flow|" + str(ev["id"]), "flowId": str(ev["id"]), "proto": str(ev.get("proto") or "tcp"),
                "state": "connecting", "raddr": raddr, "rport": int(ev.get("rport") or 0), "lport": 0,
                "pid": int(ev.get("pid") or 0), "exe": exe, "app": os.path.basename(exe) or "unknown",
                "cgroup": "", "system": False, "scope": scope, "host": str(ev.get("host") or ""),
                "cc": "", "org": "", "up": 0, "down": 0, "upRate": 0, "downRate": 0, "new": True, "list": "",
                "via": "", "viaId": "", "viaKind": "", "cmd": "", "chain": [], "unit": "", "paused": True}
        for k in ("via", "viaId", "viaKind"):     # the extension's launcher (Launcher.via, same rules as the monitor)
            conn[k] = str(ev.get(k) or "")
        live = next((c for c in self.conns if c.get("pid") == conn["pid"] and c.get("raddr") == raddr), None)
        if live:                                  # the monitor may already know more (launcher, command, country)
            for k in ("cmd", "chain", "cc", "org", "host"):
                conn[k] = live.get(k) or conn[k]
        d = M.decide(conn, self.rules, self._ctx())
        if d["verdict"] != "prompt":
            self._resolve([conn["flowId"]], d["verdict"] == "allow")
            return
        key = M.alert_key(conn)
        existing = next((a for a in self.alerts if a["key"] == key), None)
        if existing:
            existing.setdefault("flows", []).append(conn["flowId"])
            return
        alerts = list(self.alerts)
        self._queue_alert(alerts, conn, d)
        for a in alerts:
            if a["key"] == key:
                a["flows"] = [conn["flowId"]]
        self.alerts = alerts
        self.changed("alerts")

    def _send_feeds(self):
        """macOS: hand the enabled threat feeds to the extension when they change.
        Parsed like the monitor does; big lists travel once, not with every spec."""
        from .monitor.common import parse_list
        wanted = []
        for l in self.lists:
            if not l.get("enabled"):
                continue
            path = os.path.join(self.p.state_dir, "lists", re.sub(r"[^A-Za-z0-9_.-]", "_", str(l["id"])) + ".txt")
            try:
                st = os.stat(path)
            except OSError:
                continue
            wanted.append((str(l["id"]), "ip" if l.get("kind") == "ip" else "domain", path, st.st_mtime_ns, st.st_size))
        sig = tuple(wanted)
        if sig == getattr(self, "_feedsSig", None):
            return
        feeds = []
        for lid, kind, path, _, _ in wanted:
            try:
                with open(path, errors="replace") as f:
                    feeds.append({"id": lid, "kind": kind, "entries": sorted(parse_list(kind, f.read()))})
            except OSError:
                continue
        self._feedsSig = sig
        self._run(["feeds", json.dumps({"feeds": feeds}, separators=(",", ":"))])

    def _resolve(self, flow_ids, allow):
        if self.bridge and flow_ids:
            self._run(["resolve", json.dumps({"flows": list(flow_ids), "allow": bool(allow)})])

    def _sync_enforcement(self, force=False):
        if force:
            self._forceSync = True
        wait = 0.4 if self._forceSync else max(0.4, 5 - (_now() - self._lastSyncAt))
        if self._syncHandle and not force:
            return
        if self._syncHandle:
            self._syncHandle.cancel()
        self._syncHandle = asyncio.get_running_loop().call_later(wait, self._do_sync)

    def _do_sync(self):
        self._syncHandle = None
        if not self.enforce or not self.helperUsable or self.uid < 0 or self.pluginActive:
            return
        ctx = self._ctx()
        if self.bridge:
            self._send_feeds()                    # only when the feed files changed
            spec = M.build_spec_darwin(self.rules, ctx, self.prefs, self.defaultRoute, self.proxies)
            self._apply_text(json.dumps(spec, separators=(",", ":")), None)
            return
        res = M.build_spec(self.rules, ctx, self.conns, self.apps, self.ipCidrs, self.uid)
        res["spec"]["logNew"] = self.prefs.get("catchShort") is not False
        routes = M.compile_routes(self.rules, self.defaultRoute, self.proxies, ctx, self.conns, self.apps, self.uid)
        if routes and self.proxyCapable:
            res["spec"]["proxy"] = routes
            self.proxyError = ""
        elif routes:
            blocks = []
            for e in routes["rules"]:
                if e["verdict"] == "redirect":
                    d = dict(e, verdict="drop")
                    d.pop("port", None)
                    blocks.append(d)
            res["spec"]["rules"] = blocks + res["spec"]["rules"]
            if routes["defaultPort"] is not None:
                res["spec"]["silentDeny"] = True
            self.proxyError = ("Proxy routing needs citadel-helper %s or newer (installed: %s). Apps routed through a proxy "
                               "are blocked until it is updated." % (MIN_PROXY_HELPER, self.helperVersion or "unknown"))
        else:
            self.proxyError = ""
        self.approx = res["approx"]
        self.changed("approx", "proxyError")
        self._apply_text(json.dumps(res["spec"], separators=(",", ":")), res["spec"].get("proxy"))

    def _apply_text(self, text, routes):
        """Write the spec and have the helper (or the macOS host) apply it."""
        if text == self._lastSpec and not self._forceSync:
            return
        self._forceSync = False
        self._lastSpec = text
        self._lastSyncAt = _now()
        self.enforceBusy = True
        self._pendingRoutes = routes
        self.changed("enforceBusy")
        try:
            P.write_atomic(self.p.spec, text + "\n")
        except OSError:
            self.enforceBusy, self.enforceError = False, "could not write " + self.p.spec
            self.changed("enforceBusy", "enforceError")
            return

        def done(code, out, err):
            self.enforceBusy = False
            if code == 0:
                self.enforceActive, self.enforceError, self.enforceAppliedAt = True, "", _now()
                cut = M.route_cut_targets(self._appliedRoutes, self._pendingRoutes, self.conns, self.uid)
                self._appliedRoutes = self._pendingRoutes
                if cut:
                    self._kill(cut)
            else:
                self.enforceActive = False
                self._lastSpec = ""
                auth = code in (126, 127) and not self.bridge          # pkexec refused (Linux)
                self.enforceError = self._auth_help() if auth else (err or out or "helper exit %s" % code).strip()[:400]
                if auth:
                    self.enforce = False
                    self.changed("enforce")
                    self.save()
            self.changed("enforceBusy", "enforceActive", "enforceError", "enforceAppliedAt")
        self._run(["apply", self.p.spec], done)

    def _kill(self, targets):
        if not self.enforce or not self.helperUsable or not targets or self.pluginActive:
            return
        try:
            P.write_atomic(self.p.kill, json.dumps(targets) + "\n")
        except OSError:
            return
        self._run(["kill", self.p.kill])

    def _auth_help(self):
        user = pwd.getpwuid(os.getuid()).pw_name
        if self.inWheel:
            return ("Authorization was cancelled or refused. Citadel's helper needs your approval "
                    "(or the citadel-helper polkit rule).")
        return ("Not authorized. Citadel's helper runs without a password only for the %s group: "
                "sudo usermod -aG %s %s, then log out and back in." % (self.privilegedGroup, self.privilegedGroup, user))

    def setEnforce(self, on):
        if on and not self.helperInstalled:
            self.enforceError = "Install citadel-helper first: github.com/NeatOuk/citadel-helper"
            self.changed("enforceError")
            return
        if on and self.helperOutdated:
            self.enforceError = "citadel-helper %s %s. Update it before turning enforcement on." % (self.helperVersion, self.helperProblem)
            self.changed("enforceError")
            return
        self.enforce = bool(on)
        self.changed("enforce")
        self.save()
        if self.enforce:
            self._lastSpec = ""
            if self.helperUsable:
                self._sync_enforcement(True)
            else:
                self.verifyHelper()
        else:
            self.enforceBusy = True
            self.changed("enforceBusy")

            def done(code, out, err):
                self.enforceBusy = False
                self.enforceActive = code != 0 and self.enforceActive
                self.enforceError = "" if code == 0 else (err or "could not turn off").strip()[:300]
                self.changed("enforceBusy", "enforceActive", "enforceError")
            self._run(["off"], done)

    def refreshEnforceStatus(self):
        if not self.helperInstalled:
            return

        def done(code, out, err):
            try:
                s = json.loads(out)
            except ValueError:
                return
            self.enforceActive = bool(s.get("active"))
            self.enforceDrops = int(s.get("drops") or 0)
            self.helperVersion = s.get("version") or "1.1.0"
            self.helperLogging = bool(s.get("logging"))
            if self.helperOutdated and self.enforce:
                self.enforceActive = False
            self.changed("enforceActive", "enforceDrops", "helperVersion", "helperLogging")
        self._run(["status"], done)

    # ------------------------------------------------------------ proxy process
    async def _run_proxy(self):
        while True:
            if not self.proxies or self.pluginActive:
                await asyncio.sleep(1)
                continue
            try:
                self._proxy = await asyncio.create_subprocess_exec(
                    sys.executable, self.p.proxy, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
            except OSError as e:
                log.warning("proxy could not start: %s", e)
                await asyncio.sleep(3)
                continue
            self._configure_proxy()
            while True:
                line = await self._proxy.stdout.readline()
                if not line:
                    break
                try:
                    self._on_proxy_line(json.loads(line))
                except ValueError:
                    continue
            await self._proxy.wait()
            await asyncio.sleep(3)

    def _configure_proxy(self):
        pr = self._proxy
        if not self.loaded or not pr or pr.returncode is not None:
            return
        if not self.proxies:
            pr.stdin.close()                      # it exits when stdin closes
            return
        pr.stdin.write((json.dumps({"cmd": "config", "checkEvery": 30, "proxies": self.proxies}) + "\n").encode())

    def _on_proxy_line(self, m):
        t = m.get("type")
        now = _now()
        if t in ("status", "check"):
            target = self.proxyStatus if t == "status" else self.proxyCheck
            target = dict(target, **{m.get("id"): {"ok": bool(m.get("ok")), "ms": m.get("ms") or 0,
                                                   "error": m.get("error") or "", "ts": now}})
            if t == "status":
                self.proxyStatus = target
            else:
                self.proxyCheck = target
            self.changed("proxyStatus", "proxyCheck")
        elif t == "error":
            self._proxyFailed = {k: v for k, v in self._proxyFailed.items() if v > self.now - 60}
            self._proxyFailed["%s|%s" % (m.get("dst"), m.get("port"))] = self.now
            px = next((x for x in self.proxies if x["id"] == m.get("id")), None)
            name = px["name"] if px else m.get("id")
            entry = {"ts": now, "proxy": name, "dst": m.get("dst"), "port": m.get("port"), "error": m.get("error")}
            last = self.proxyLog[0] if self.proxyLog else None
            if last and last["proxy"] == name and last["dst"] == m.get("dst") and entry["ts"] - last["ts"] < 60:
                return
            self.proxyLog = ([entry] + self.proxyLog)[:50]
            self.changed("proxyLog")
            self._log([{"ts": self.now, "app": "via " + name, "exe": "", "via": "", "dest": m.get("dst"), "ip": m.get("dst"),
                        "port": m.get("port"), "cc": "", "verdict": "deny", "source": "proxy %s unreachable" % name}])
        elif t == "stats":
            self.proxyCarried = [x for x in self.proxyCarried if x["ts"] > self.now - 300] + [{"ts": self.now, "counts": m.get("counts") or {}}]
            self.changed("proxyCarried")
        elif t == "log":
            log.warning("proxy: %s", m.get("msg"))

    def saveProxy(self, fields, user="", password=""):
        ptype = fields.get("type") if fields.get("type") in ("http", "https", "socks5") else "http"
        port = M.norm_port(fields.get("port"))
        host = str(fields.get("host") or "").strip()
        if not host or port == "*":
            return {"error": "Enter a host and a port (1–65535)."}
        old = next((x for x in self.proxies if x["id"] == fields.get("id")), None)
        pid = old["id"] if old else "px" + M._new_id()[:8]
        auth = False if user is None else (True if user else bool(old and old.get("auth")))
        px = {"id": pid, "name": str(fields.get("name") or host).strip(), "type": ptype, "host": host, "port": port,
              "listen": old["listen"] if old else M.free_listen_port(self.proxies), "auth": auth,
              "verifyTls": fields.get("verifyTls") is not False}
        if not px["listen"]:
            return {"error": "Too many proxies."}
        self.proxies = [px if x["id"] == pid else x for x in self.proxies] if old else self.proxies + [px]
        self.changed("proxies")
        self.save()
        self._send_config()
        if user:
            P.store_secret(pid, px["name"], user, password or "")
        elif user is None:
            P.clear_secret(pid)
        self._configure_proxy()
        if self.enforce:
            self._sync_enforcement(True)
        return {"error": "", "id": pid}

    def removeProxy(self, id):
        self.proxies = [x for x in self.proxies if x["id"] != id]
        self.proxyStatus = {k: v for k, v in self.proxyStatus.items() if k != id}
        self.proxyCheck = {k: v for k, v in self.proxyCheck.items() if k != id}
        if self.defaultRoute == id:
            self.defaultRoute = "direct"
        P.clear_secret(id)
        self.changed("proxies", "proxyStatus", "proxyCheck", "defaultRoute")
        self.save()
        self._configure_proxy()
        if self.enforce:
            self._sync_enforcement(True)

    def checkProxy(self, id):
        self.proxyCheck = dict(self.proxyCheck, **{id: {"pending": True}})
        self.changed("proxyCheck")
        pr = self._proxy
        if pr and pr.returncode is None:
            pr.stdin.write((json.dumps({"cmd": "check", "id": id}) + "\n").encode())

    def setDefaultRoute(self, route):
        self.defaultRoute = route if route == "direct" or any(x["id"] == route for x in self.proxies) else "direct"
        self.changed("defaultRoute")
        self.save()
        if self.enforce:
            self._sync_enforcement(True)

    # ------------------------------------------------------------ explain
    def _explain_agent(self):
        if str(self.prefs.get("explainCommand") or "").strip():
            return "custom command"
        return (self.prefs.get("explainAgent") or "").strip() or self.defaultAgent or \
            (self.installedAgents[0] if self.installedAgents else "")

    async def _agents_watch(self):
        while True:
            try:
                proc = await asyncio.create_subprocess_exec(sys.executable, self.p.explain, "--list-agents",
                                                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                out, _ = await proc.communicate()
                info = json.loads(out.decode().strip().splitlines()[-1])
                if info.get("agents") != self.installedAgents or (info.get("default") or "") != self.defaultAgent:
                    self.installedAgents, self.defaultAgent = info.get("agents") or [], info.get("default") or ""
                    self.changed("installedAgents", "defaultAgent")
            except (OSError, ValueError, IndexError):
                pass
            await asyncio.sleep(60)

    @staticmethod
    def explainKey(conn):
        return "%s|%s|%s" % (conn.get("exe") or conn.get("app") or "?", conn.get("host") or conn.get("raddr") or "",
                             conn.get("rport") or "")

    def _set_explanation(self, key, value):
        self.explanations = dict(self.explanations, **{key: value})
        self.alerts = [dict(a, firstSeen=self.now) if self.explainKey(a["conn"]) == key else a for a in self.alerts]
        self.changed("explanations", "alerts")

    def explain(self, conn, fresh=False):
        agent = self._explain_agent()
        if not conn or not agent:
            return
        key = self.explainKey(conn)
        if (self.explanations.get(key) or {}).get("state") == "pending":
            return
        self._set_explanation(key, {"state": "pending", "agent": agent})
        c = {k: conn.get(k) or d for k, d in (("app", ""), ("exe", ""), ("via", ""), ("cmd", ""), ("host", ""), ("raddr", ""),
                                               ("rport", 0), ("proto", "tcp"), ("cc", ""), ("org", ""))}
        self._explainQueue.put_nowait({"key": key, "req": {"conn": c, "fresh": bool(fresh)}})

    def testExplain(self):
        self.explainTestResult = {"state": "pending", "agent": self._explain_agent()}
        self.changed("explainTestResult")
        self._explainQueue.put_nowait({"key": "", "test": True, "req": {"test": True}})

    async def _explain_loop(self):
        while True:
            job = await self._explainQueue.get()
            job["req"]["prefs"] = {"explainCommand": self.prefs.get("explainCommand") or "",
                                   "explainModel": self.prefs.get("explainModel") or "",
                                   "explainAgent": self.prefs.get("explainAgent") or ""}
            env = dict(os.environ, CITADEL_STATE_DIR=self.p.state_dir, CITADEL_AGENT_FILE=self.p.agent_file)
            r = None
            try:
                proc = await asyncio.create_subprocess_exec(sys.executable, self.p.explain, stdin=asyncio.subprocess.PIPE,
                                                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=env)
                out, _ = await asyncio.wait_for(proc.communicate(json.dumps(job["req"]).encode()), 180)
                r = json.loads(out.decode().strip().splitlines()[-1])
            except (OSError, ValueError, IndexError, asyncio.TimeoutError):
                r = None
            agent = self._explain_agent()
            if not r:
                v = {"state": "error", "code": "failed", "error": "Citadel explain gave no answer.", "agent": agent}
            elif r.get("ok"):
                v = {"state": "done", "result": r.get("result"), "agent": r.get("agent"), "model": r.get("model") or "",
                     "cached": bool(r.get("cached"))}
            else:
                v = {"state": "error", "code": r.get("code") or "failed", "error": r.get("error") or "failed",
                     "agent": r.get("agent") or agent}
            if job.get("test"):
                self.explainTestResult = v
                self.changed("explainTestResult")
            else:
                self._set_explanation(job["key"], v)

    # ------------------------------------------------------------ the Omarchy plugin
    def _plugin_running(self):
        """Is another Citadel core (the Omarchy plugin's monitor) running for this user?"""
        if self._besidePlugin:
            return False
        return P.other_core_running(self._pluginMarker, [self.p.monitor])

    async def _plugin_watch(self):
        while True:
            active = self._plugin_running()
            if active != self.pluginActive:
                if active:
                    self._pause()
                else:
                    self._resume()
            await asyncio.sleep(2)

    def _pause(self):
        log.warning("the Citadel Omarchy plugin is active: pausing (no monitor, firewall or state writes)")
        if self._saveHandle:
            self._saveHandle.cancel()
            self._saveHandle = None
        if self._syncHandle:
            self._syncHandle.cancel()
            self._syncHandle = None
        self.pluginActive = True
        for proc in (self._monitor, self._proxy):
            if proc and proc.returncode is None:
                try:
                    if proc.stdin:
                        proc.stdin.close()
                    proc.terminate()
                except ProcessLookupError:
                    pass
        for key in list(self._notifications):
            self._close_notification(key)
        self.conns, self.groups, self.alerts, self.decisions, self.recentShort = [], [], [], {}, []
        self.monitorUp = False
        self.changed("pluginActive", "conns", "groups", "alerts", "decisions", "recentShort", "monitorUp")

    def _resume(self):
        log.warning("the Citadel Omarchy plugin stopped: resuming")
        self.pluginActive = False
        self.ticks = 0
        self._lastSpec = ""
        self._load()                     # the plugin may have changed the policies
        self.changed("pluginActive")
        if self.enforce:
            self._sync_enforcement(True)

    # ------------------------------------------------------------ lifecycle
    async def start(self):
        os.makedirs(os.path.dirname(self.p.spec), exist_ok=True)
        self.privilegedGroup, self.inWheel = P.privileged_group()
        self.pluginActive = self._plugin_running()
        if self.pluginActive:
            log.warning("the Citadel Omarchy plugin is active: starting paused")
        self._load()
        loop = asyncio.get_running_loop()
        for coro in (self._flush_loop(), self._clock_loop(), self._run_monitor(), self._run_proxy(), self._helper_loop(),
                     self._helper_watch(), self._explain_loop(), self._agents_watch(), self._plugin_watch()) + \
                ((self.bridge.events(self._on_host_event),) if self.bridge else ()):
            self._tasks.append(loop.create_task(coro))

    async def stop(self):
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        procs = [p for p in (self._monitor, self._proxy) + tuple(self._notifications.values()) if p and p.returncode is None]
        for proc in procs:
            try:
                if proc.stdin:
                    proc.stdin.close()
                proc.terminate()
            except (ProcessLookupError, AttributeError):
                pass
        for proc in procs:
            try:
                await asyncio.wait_for(proc.wait(), 3)
            except asyncio.TimeoutError:
                proc.kill()
        self._notifications.clear()
        if self._saveHandle:
            self._saveHandle.cancel()
            self._write_state()


def _app_with_origin(conn):
    app = conn.get("app") or (conn.get("exe").split("/")[-1] if conn.get("exe") else "unknown")
    via = conn.get("via")
    return app + ((" in " if conn.get("viaKind") == "terminal" else " via ") + via if via else "")
