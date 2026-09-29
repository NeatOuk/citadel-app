"""The daemon end to end, with a fake monitor and a fake helper.

A fake citadel-monitor replays ticks written by the test; a fake enforcer
records every call and answers `status` with a chosen version. The real
socket API is used, so this covers api.py as well. Nothing privileged runs.
"""
import asyncio
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel.api import Server  # noqa: E402
from citadel.daemon import Daemon, Paths  # noqa: E402

FAKE_MONITOR = r'''#!/usr/bin/env python3
# replays ticks: each line of $FAKE_TICKS (a file the test appends to) is sent once
import json, os, sys, time, select
path = os.environ["FAKE_TICKS"]
sent = 0
while True:
    r, _, _ = select.select([sys.stdin], [], [], 0.05)
    if r and not sys.stdin.readline():
        break
    try:
        lines = open(path).read().splitlines()
    except OSError:
        lines = []
    for line in lines[sent:]:
        print(line, flush=True)
    sent = len(lines)
'''
FAKE_HELPER = r'''#!/usr/bin/env python3
import json, os, sys
log = os.environ["FAKE_HELPER_LOG"]
entry = {"args": sys.argv[1:]}
if sys.argv[1:2] in (["apply"], ["kill"]):
    entry["file"] = json.load(open(sys.argv[2]))
open(log, "a").write(json.dumps(entry) + "\n")
if sys.argv[1] == "status":
    print(json.dumps({"active": True, "drops": 0, "rules": 1, "logging": True, "proxy": False,
                      "version": os.environ.get("FAKE_HELPER_VERSION", "1.3.0")}))
'''
FAKE_EXPLAIN = r'''#!/usr/bin/env python3
import json, sys
if sys.argv[1:] == ["--list-agents"]:
    print(json.dumps({"agents": ["pi"], "default": ""})); sys.exit(0)
req = json.load(sys.stdin)
print(json.dumps({"ok": True, "agent": "pi", "model": "", "cached": False,
                  "result": {"company": "Example", "service": "Web", "purpose": "test", "category": "other",
                             "risk": "low", "suggestion": "allow", "why": "x", "confidence": "high"}}))
'''

SLICE = "user.slice/user-%d.slice/user@%d.service/app.slice/" % (os.getuid(), os.getuid())


def conn(key, exe, raddr, rport=443, host="", new=True, **kw):
    c = {"key": key, "exe": exe, "app": exe.split("/")[-1], "raddr": raddr, "rport": rport, "host": host, "proto": "tcp",
         "cgroup": SLICE + "app-x.scope", "system": False, "scope": "internet", "new": new, "pid": 4242,
         "up": 0, "down": 0, "upRate": 0, "downRate": 0, "list": "", "via": "", "viaId": "", "viaKind": "", "cmd": ""}
    c.update(kw)
    return c


def tick(conns, ts=None):
    return json.dumps({"type": "tick", "ts": ts or 1000.0, "uid": os.getuid(), "selfPid": 1, "conns": conns,
                       "apps": {"/usr/bin/curl": {"name": "curl", "pids": [4242], "cgroups": [SLICE + "app-x.scope"],
                                                  "owned": [SLICE + "app-x.scope"], "trust": {"level": "verified", "hash": "h1"}}},
                       "network": {"names": ["Home Wi-Fi"], "ssid": "Home Wi-Fi"}})


class Client:
    def __init__(self, path):
        self.path = path
        self.n = 0
        self.state = {}
        self.events = []

    async def connect(self):
        self.r, self.w = await asyncio.open_unix_connection(self.path, limit=16 * 1024 * 1024)
        self.pending = {}
        self.task = asyncio.create_task(self._read())

    async def _read(self):
        while True:
            line = await self.r.readline()
            if not line:
                return
            m = json.loads(line)
            if m["type"] == "state":
                self.state.update(m["data"])
            elif m["type"] == "reply":
                self.pending.pop(m["id"]).set_result(m)
            else:
                self.events.append(m)

    async def call(self, cmd, *args):
        self.n += 1
        fut = asyncio.get_running_loop().create_future()
        self.pending[self.n] = fut
        self.w.write((json.dumps({"id": self.n, "cmd": cmd, "args": list(args)}) + "\n").encode())
        return await asyncio.wait_for(fut, 5)

    async def wait_for(self, pred, timeout=5.0):
        end = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < end:
            if pred(self.state):
                return True
            await asyncio.sleep(0.05)
        return False


class DaemonTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        os.makedirs(t + "/libexec")
        for name, body in (("citadel-monitor", FAKE_MONITOR), ("citadel-explain", FAKE_EXPLAIN), ("citadel-proxy", "")):
            with open(t + "/libexec/" + name, "w") as f:
                f.write(body)
        with open(t + "/helper", "w") as f:
            f.write(FAKE_HELPER)
        os.chmod(t + "/helper", 0o755)
        self.ticks = t + "/ticks"
        self.hlog = t + "/helper.log"
        env = {"CITADEL_STATE_DIR": t + "/state", "CITADEL_RUNTIME_DIR": t + "/run", "CITADEL_LIBEXEC": t + "/libexec",
               "CITADEL_HELPER": t + "/helper", "CITADEL_PKEXEC": "", "FAKE_TICKS": self.ticks,
               "CITADEL_HELPER_TRANSPORT": "pkexec",              # the fake Linux helper, on macOS too
               "FAKE_HELPER_LOG": self.hlog, "CITADEL_AGENT_FILE": t + "/agent", "PATH": "/usr/bin:/bin",
               # detect only this test's fake plugin, not a real one running on the machine
               "CITADEL_PLUGIN_MARKER": "fake-plugin-monitor-%d" % os.getpid()}
        self.saved_env = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        self.d = Daemon(Paths())
        self.srv = Server(self.d, self.d.p.socket)
        await self.srv.start()
        await self.d.start()
        self.c = Client(self.d.p.socket)
        await self.c.connect()

    async def asyncTearDown(self):
        self.c.task.cancel()
        self.c.w.close()
        await self.d.stop()
        await self.srv.stop()
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def feed(self, line):
        with open(self.ticks, "a") as f:
            f.write(line + "\n")

    def helper_calls(self):
        try:
            with open(self.hlog) as f:
                return [json.loads(l) for l in f]
        except OSError:
            return []

    async def test_full_state_on_connect(self):
        self.assertTrue(await self.c.wait_for(lambda s: "rules" in s and "helperUsable" in s))
        self.assertEqual(self.c.state["mode"], "guarded")

    async def test_gate_request_and_answer(self):
        self.d.prefs["notify"] = False
        self.feed(tick([]))
        self.assertTrue(await self.c.wait_for(lambda s: s.get("ticks", 0) >= 1))
        self.feed(tick([conn("k1", "/usr/bin/curl", "93.184.216.34", host="example.com")], ts=1002))
        self.assertTrue(await self.c.wait_for(lambda s: len(s.get("alerts", [])) == 1), "alert queued")
        key = self.c.state["alerts"][0]["key"]
        r = await self.c.call("answer", key, "allow", "host", "forever")
        self.assertTrue(r["ok"] and r["result"])
        self.assertTrue(await self.c.wait_for(lambda s: len(s["alerts"]) == 0 and len(s["rules"]) == 1))
        rule = self.c.state["rules"][0]
        self.assertEqual((rule["app"], rule["host"], rule["action"], rule["origin"], rule["exeHash"]),
                         ("/usr/bin/curl", "example.com", "allow", "gate", "h1"))
        await asyncio.sleep(0.5)
        with open(self.d.p.state) as f:
            saved = json.load(f)
        self.assertEqual(len(saved["rules"]), 1, "state.json written")

    async def test_enforcement_goes_through_the_helper_gate(self):
        self.feed(tick([conn("k1", "/usr/bin/curl", "1.1.1.1", new=False)]))
        self.assertTrue(await self.c.wait_for(lambda s: s.get("helperVersion") == "1.3.0"), "helper verified")
        await self.c.call("addRule", {"app": "/usr/bin/curl", "host": "1.1.1.1", "action": "deny"})
        await self.c.call("setEnforce", True)
        self.assertTrue(await self.c.wait_for(lambda s: s.get("enforceAppliedAt", 0) > 0, 6), "spec applied")
        applies = [c for c in self.helper_calls() if c["args"][0] == "apply"]
        self.assertTrue(applies)
        rules = applies[-1]["file"]["rules"]
        self.assertIn({"verdict": "drop", "cgroup": SLICE + "app-x.scope", "targets": [{"ip": "1.1.1.1", "port": None}]}, rules)
        await self.c.call("setMode", "lockdown", 0)
        await asyncio.sleep(1)
        self.assertTrue([c for c in self.helper_calls() if c["args"][0] == "apply"][-1]["file"]["silentDeny"])

    async def test_old_helper_never_gets_apply_or_kill(self):
        await self.d.stop()
        await self.srv.stop()
        os.environ["FAKE_HELPER_VERSION"] = "1.1.0"
        try:
            self.d = Daemon(Paths())
            self.srv = Server(self.d, self.d.p.socket)
            await self.srv.start()
            await self.d.start()
            self.c = Client(self.d.p.socket)
            await self.c.connect()
            self.assertTrue(await self.c.wait_for(lambda s: s.get("helperVersion") == "1.1.0"))
            self.d.enforce = True
            self.d._sync_enforcement(True)
            self.d._kill([{"cgroup": SLICE + "app-x.scope", "ip": "1.1.1.1"}])
            r = await self.c.call("setEnforce", True)
            await asyncio.sleep(1)
            self.assertFalse([c for c in self.helper_calls() if c["args"][0] in ("apply", "kill")])
            self.assertIn("security bug", self.c.state.get("enforceError", ""))
        finally:
            os.environ.pop("FAKE_HELPER_VERSION", None)

    OLD = "/home/u/.local/share/mise/installs/claude/2.1.281/claude"
    NEW = "/home/u/.local/share/mise/installs/claude/2.1.283/claude"

    async def _updated_app_waits(self):
        self.d.prefs["notify"] = False
        await self.c.call("addRule", {"app": self.OLD, "action": "allow"})
        await self.c.call("addRule", {"app": self.OLD, "host": "bad.example", "action": "deny"})
        self.feed(tick([]))
        self.assertTrue(await self.c.wait_for(lambda s: s.get("ticks", 0) >= 1))
        self.feed(tick([conn("k1", self.NEW, "1.1.1.1"), conn("k2", self.NEW, "2.2.2.2", host="api.example")], ts=time.time()))
        self.assertTrue(await self.c.wait_for(lambda s: len(s.get("alerts", [])) >= 1))
        await asyncio.sleep(0.3)
        self.assertEqual(len(self.c.state["alerts"]), 1, "one request for the update, not one per connection")
        a = self.c.state["alerts"][0]
        self.assertEqual((a["key"], a["updatedFrom"], a["policies"]), ("update|" + self.NEW, self.OLD, 2))
        return a

    async def test_updated_app_keeps_its_policies(self):
        a = await self._updated_app_waits()
        self.assertTrue((await self.c.call("answer", a["key"], "keep"))["result"])
        self.assertTrue(await self.c.wait_for(lambda s: s["alerts"] == [] and s["decisions"].get("k1", {}).get("verdict") == "allow"))
        self.assertEqual(sorted((r["app"], r["host"]) for r in self.c.state["rules"]),
                         [(self.NEW, "*"), (self.NEW, "bad.example")])

    async def test_updated_app_can_be_treated_as_new(self):
        a = await self._updated_app_waits()
        await self.c.call("answer", a["key"], "new")
        self.assertTrue(await self.c.wait_for(lambda s: len(s["alerts"]) == 2))
        self.assertFalse([x for x in self.c.state["alerts"] if x.get("updatedFrom")])
        self.assertEqual({r["app"] for r in self.c.state["rules"]}, {self.OLD}, "the old version keeps its policies")

    async def test_one_notification_per_app_and_its_buttons_answer_all(self):
        from citadel import platform as P
        posted = []

        class FakeProc:
            returncode = None

            def __init__(self):
                self.done = asyncio.get_running_loop().create_future()
                self.stdout = self

            async def read(self):
                return await self.done

            def terminate(self):
                self.returncode = 0
                if not self.done.done():
                    self.done.set_result(b"")

        async def fake_notify(title, body, actions):
            posted.append({"title": title, "body": body, "actions": [a for a, _ in actions], "proc": FakeProc()})
            return posted[-1]["proc"]
        saved = P.notify
        P.notify = fake_notify
        try:
            self.feed(tick([]))
            self.assertTrue(await self.c.wait_for(lambda s: s.get("ticks", 0) >= 1))
            self.feed(tick([conn("k1", "/usr/bin/curl", "1.1.1.1"), conn("k2", "/usr/bin/curl", "2.2.2.2"),
                            conn("k3", "/usr/bin/curl", "3.3.3.3", host="three.example")], ts=time.time()))
            self.assertTrue(await self.c.wait_for(lambda s: len(s.get("alerts", [])) == 3))
            await asyncio.sleep(0.8)
            self.assertEqual(len(posted), 1, "one notification for the burst")
            self.assertIn("and 1 more", posted[0]["body"])
            self.assertIn("app", posted[0]["actions"])
            posted[0]["proc"].done.set_result(b"app\n")                    # "Allow the app"
            self.assertTrue(await self.c.wait_for(lambda s: s["alerts"] == []))
            self.assertEqual([(r["app"], r["host"], r["action"]) for r in self.c.state["rules"]],
                             [("/usr/bin/curl", "*", "allow")])
        finally:
            P.notify = saved

    async def test_block_answer_cuts_live_connections(self):
        self.d.prefs["notify"] = False
        self.feed(tick([]))
        self.assertTrue(await self.c.wait_for(lambda s: s.get("helperVersion") == "1.3.0"))
        await self.c.call("setEnforce", True)
        self.feed(tick([conn("k2", "/usr/bin/curl", "6.6.6.6")], ts=1003))
        self.assertTrue(await self.c.wait_for(lambda s: len(s.get("alerts", [])) == 1))
        await self.c.call("answer", self.c.state["alerts"][0]["key"], "deny", "host", "forever")
        await asyncio.sleep(1)
        kills = [c for c in self.helper_calls() if c["args"][0] == "kill"]
        self.assertTrue(kills and {"cgroup": SLICE + "app-x.scope", "ip": "6.6.6.6"} in kills[-1]["file"])

    async def test_citadel_proxy_tunnels_never_wait_at_the_gate(self):
        self.d.prefs["notify"] = False
        self.feed(tick([]))
        self.assertTrue(await self.c.wait_for(lambda s: s.get("ticks", 0) >= 1))
        own = conn("k9", "/usr/bin/python3.14", "192.168.1.20", 3128, app="Citadel proxy",
                   cmd="python3 /usr/lib/citadel/libexec/citadel-proxy")
        self.feed(tick([own], ts=1004))
        self.assertTrue(await self.c.wait_for(lambda s: "k9" in s.get("decisions", {})))
        self.assertEqual(self.c.state["decisions"]["k9"]["source"], "citadel")
        self.assertEqual(self.c.state["alerts"], [])

    @unittest.skipUnless(sys.platform.startswith("linux"), "the Omarchy plugin exists on Linux only")
    async def test_pauses_while_the_omarchy_plugin_runs(self):
        self.feed(tick([conn("k1", "/usr/bin/curl", "1.1.1.1", new=False)]))
        self.assertTrue(await self.c.wait_for(lambda s: s.get("helperVersion") == "1.3.0"))
        await self.c.call("setEnforce", True)
        self.assertTrue(await self.c.wait_for(lambda s: s.get("enforceAppliedAt", 0) > 0, 6))
        await asyncio.sleep(0.5)
        before = len(self.helper_calls())
        mtime = os.path.getmtime(self.d.p.state)
        fake = os.path.join(self.tmp.name, "neat.citadel", "bin", os.environ["CITADEL_PLUGIN_MARKER"])
        os.makedirs(os.path.dirname(fake))
        with open(fake, "w") as f:
            f.write("import time\ntime.sleep(60)\n")
        plugin = await asyncio.create_subprocess_exec(sys.executable, fake)
        try:
            self.assertTrue(await self.c.wait_for(lambda s: s.get("pluginActive") is True, 8), "paused")
            self.assertFalse(self.c.state["monitorUp"])
            r = await self.c.call("addRule", {"app": "/usr/bin/curl", "action": "deny"})
            self.assertFalse(r["ok"])
            self.assertIn("Omarchy plugin", r["error"])
            self.d._sync_enforcement(True)
            self.d._kill([{"cgroup": SLICE + "app-x.scope", "ip": "1.1.1.1"}])
            await asyncio.sleep(1)
            self.assertEqual(len(self.helper_calls()), before, "no helper call while paused")
            self.assertEqual(os.path.getmtime(self.d.p.state), mtime, "state.json untouched while paused")
            # the plugin changes the policies meanwhile
            with open(self.d.p.state) as f:
                st = json.load(f)
            st["rules"].append({"id": "fromPlugin", "app": "/usr/bin/git", "action": "allow"})
            with open(self.d.p.state, "w") as f:
                json.dump(st, f)
        finally:
            plugin.terminate()
            await plugin.wait()
        self.assertTrue(await self.c.wait_for(lambda s: s.get("pluginActive") is False, 8), "resumed")
        self.assertTrue(await self.c.wait_for(lambda s: any(r["id"] == "fromPlugin" for r in s.get("rules", []))),
                        "reloaded the plugin's policies")
        self.assertTrue(await self.c.wait_for(lambda s: s.get("monitorUp") is True, 6))

    async def test_import_batch_and_local_feed(self):
        r = await self.c.call("importRules", json.dumps([{"host": "a.example.com", "action": "deny"},
                                                         {"host": "b.example.com", "action": "allow"}]))
        self.assertTrue(r["ok"])
        self.assertTrue(await self.c.wait_for(lambda s: len(s.get("rules", [])) == 2))
        r = await self.c.call("importFeed", "Imported list (3)", ["x.example.com", "Y.example.com", "bad domain"], "")
        lid = r["result"]
        self.assertTrue(lid.startswith("import-"))
        path = os.path.join(self.d.p.state_dir, "lists", lid + ".txt")
        with open(path) as f:
            self.assertEqual(f.read().split(), ["x.example.com", "y.example.com"])
        self.assertTrue(await self.c.wait_for(lambda s: any(l["id"] == lid and l.get("local") for l in s.get("lists", []))))
        await self.c.call("removeList", lid)
        self.assertTrue(await self.c.wait_for(lambda s: not any(l["id"] == lid for l in s.get("lists", []))))
        self.assertFalse(os.path.exists(path), "an imported list's file is removed with it")

    async def test_unknown_command_is_refused(self):
        r = await self.c.call("_write_state")
        self.assertFalse(r["ok"])
        r = await self.c.call("setPref", "notARealPref", 1)
        self.assertTrue(r["ok"])
        self.assertNotIn("notARealPref", self.d.prefs)

    async def test_explain_through_the_queue(self):
        self.assertTrue(await self.c.wait_for(lambda s: s.get("installedAgents") == ["pi"]))
        c0 = conn("k3", "/usr/bin/curl", "93.184.216.34", host="example.com")
        await self.c.call("explain", c0, False)
        key = "/usr/bin/curl|example.com|443"
        self.assertTrue(await self.c.wait_for(lambda s: (s.get("explanations", {}).get(key) or {}).get("state") == "done"))
        self.assertEqual(self.c.state["explanations"][key]["result"]["company"], "Example")


if __name__ == "__main__":
    unittest.main()
