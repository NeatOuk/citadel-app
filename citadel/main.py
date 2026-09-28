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
    ap.add_argument("--version", action="version", version=VERSION)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    paths = Paths()
    if a.selftest:
        return selftest(paths)

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
    check("iproute2 (ss)", bool(_which("ss")))
    check("cgroup v2", os.path.exists("/sys/fs/cgroup/cgroup.controllers"))
    check("helper installed (optional)", True, "yes" if os.access(paths.helper, os.X_OK) else "no: watch-only")
    try:
        from . import model
        check("decision model", model.decide({"exe": "/x"}, [], {"mode": "guarded"})["verdict"] == "prompt")
    except Exception as e:                           # noqa: BLE001
        check("decision model", False, str(e))
    return 0 if all(checks) else 1


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
