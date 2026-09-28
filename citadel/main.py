"""Entry points: `citadel-daemon` (the service) and `citadel` (a small CLI)."""
import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import sys

from .daemon import Daemon, Paths, VERSION
from .api import Server


def daemon_main(argv=None):
    ap = argparse.ArgumentParser(prog="citadel-daemon", description="Citadel's background service")
    ap.add_argument("--selftest", action="store_true", help="check the environment and exit")
    ap.add_argument("--install-agent", action="store_true", help="macOS: start citadel-daemon at login (launchd)")
    ap.add_argument("--remove-agent", action="store_true", help="macOS: stop starting it at login")
    ap.add_argument("--version", action="version", version=VERSION)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    paths = Paths()
    if a.selftest:
        return selftest(paths)
    if a.install_agent or a.remove_agent:
        return launch_agent(install=a.install_agent)

    async def run():
        d = Daemon(paths)
        srv = Server(d, paths.socket)
        await srv.start()
        await d.start()
        logging.info("citadel-daemon %s listening on %s", VERSION, paths.socket)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        await d.stop()
        await srv.stop()
    asyncio.run(run())
    return 0


def selftest(paths):
    checks = []

    def check(name, ok, note=""):
        checks.append(ok)
        print("%s %s%s" % ("ok  " if ok else "FAIL", name, " (%s)" % note if note else ""))
    for label, path in (("monitor", paths.monitor), ("proxy", paths.proxy), ("explain", paths.explain)):
        check(label + " script", os.path.exists(path), path)
    if sys.platform == "darwin":
        for tool in ("lsof", "nettop", "ps", "codesign", "spctl", "netstat", "networksetup"):
            check(tool, bool(_which(tool)))
        check("blocking (Network Extension)", True, "not yet: watch-only (phase 2)")
    else:
        check("iproute2 (ss)", bool(_which("ss")))
        check("cgroup v2", os.path.exists("/sys/fs/cgroup/cgroup.controllers"))
        check("helper installed (optional)", True, "yes" if os.access(paths.helper, os.X_OK) else "no: watch-only")
    try:
        from . import model
        check("decision model", model.decide({"exe": "/x"}, [], {"mode": "guarded"})["verdict"] == "prompt")
    except Exception as e:                           # noqa: BLE001
        check("decision model", False, str(e))
    return 0 if all(checks) else 1


AGENT_LABEL = "io.github.neatouk.citadel"
AGENT_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%(label)s</string>
  <key>ProgramArguments</key>
  <array><string>%(python)s</string><string>%(daemon)s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>%(log)s</string>
</dict>
</plist>
"""


def launch_agent(install=True):
    """macOS: run citadel-daemon at login through a launchd user agent."""
    if sys.platform != "darwin":
        print("launchd agents are macOS only; on Linux: systemctl --user enable --now citadel", file=sys.stderr)
        return 2
    import subprocess
    path = os.path.expanduser("~/Library/LaunchAgents/%s.plist" % AGENT_LABEL)
    domain = "gui/%d" % os.getuid()
    subprocess.run(["launchctl", "bootout", domain + "/" + AGENT_LABEL], capture_output=True)
    if not install:
        if os.path.exists(path):
            os.unlink(path)
        print("removed", path)
        return 0
    daemon = os.path.realpath(sys.argv[0])
    logdir = os.path.expanduser("~/Library/Logs")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(logdir, exist_ok=True)
    with open(path, "w") as f:
        f.write(AGENT_PLIST % {"label": AGENT_LABEL, "python": sys.executable, "daemon": daemon,
                               "log": os.path.join(logdir, "citadel-daemon.log")})
    r = subprocess.run(["launchctl", "bootstrap", domain, path], capture_output=True, text=True)
    print(("installed and started: " if r.returncode == 0 else "installed, but launchctl said: " + r.stderr.strip() + "\n") + path)
    return r.returncode


def _which(x):
    import shutil
    return shutil.which(x)


def cli_main(argv=None):
    ap = argparse.ArgumentParser(prog="citadel", description="Talk to citadel-daemon")
    ap.add_argument("cmd", help="status | state | rules | alerts | guard | open | lockdown | enforce on|off | call NAME [JSON args]")
    ap.add_argument("rest", nargs="*")
    a = ap.parse_args(argv)
    path = Paths().socket
    if a.cmd == "guard":
        cmd, args = "setMode", ["guarded", 0]
    elif a.cmd == "lockdown":
        cmd, args = "setMode", ["lockdown", 0]
    elif a.cmd == "open":
        cmd, args = "setMode", ["open", int(a.rest[0]) if a.rest else 60]
    elif a.cmd == "enforce":
        cmd, args = "setEnforce", [bool(a.rest and a.rest[0] in ("on", "1", "true"))]
    elif a.cmd in ("rules", "alerts"):
        cmd, args = "state", []
    elif a.cmd == "call":
        cmd, args = a.rest[0], json.loads(a.rest[1]) if len(a.rest) > 1 else []
    else:
        cmd, args = a.cmd, []
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
    except OSError:
        print("citadel-daemon is not running (%s). Start it: systemctl --user enable --now citadel" % path, file=sys.stderr)
        return 2
    f = s.makefile("rwb")
    f.write((json.dumps({"id": 1, "cmd": cmd, "args": args}) + "\n").encode())
    f.flush()
    for line in f:
        m = json.loads(line)
        if m.get("type") == "reply" and m.get("id") == 1:
            if not m.get("ok"):
                print("error:", m.get("error"), file=sys.stderr)
                return 1
            r = m.get("result")
            if a.cmd == "rules":
                r = r["rules"]
            elif a.cmd == "alerts":
                r = r["alerts"]
            print(json.dumps(r, indent=2))
            return 0
    return 1
