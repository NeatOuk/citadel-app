"""The macOS bridge and gate, on any OS: the daemon with the host transport
(CITADEL_HELPER_TRANSPORT=host) against a fake Citadel host app.

The fake host answers status/apply/off/resolve like the Swift host does and
pushes "flow" events (connections the network extension paused).
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel.api import Server  # noqa: E402
from citadel.daemon import Daemon, Paths  # noqa: E402
from tests.test_daemon import FAKE_MONITOR, FAKE_EXPLAIN, Client, tick  # noqa: E402


class FakeHost:
    def __init__(self, path):
        self.path = path
        self.requests = []
        self.subscribers = []

    async def start(self):
        self.server = await asyncio.start_unix_server(self._client, path=self.path)

    async def stop(self):
        self.server.close()
        for w in self.subscribers:
            w.close()

    async def _client(self, reader, writer):
        line = await reader.readline()
        if not line:
            return
        msg = json.loads(line)
        if msg.get("cmd") == "subscribe":
            self.subscribers.append(writer)
            return
        self.requests.append(msg)
        out = ""
        if msg["cmd"] == "status":
            out = json.dumps({"active": True, "drops": 0, "rules": 0, "logging": False, "proxy": False,
                              "version": "1.3.0", "impl": "fake-host"})
        writer.write((json.dumps({"id": msg.get("id"), "code": 0, "out": out, "err": ""}) + "\n").encode())
        await writer.drain()
        writer.close()

    def pause(self, flow_id, exe, raddr, rport=443, host=""):
        ev = {"type": "flow", "id": flow_id, "exe": exe, "raddr": raddr, "rport": rport, "host": host, "proto": "tcp",
              "pid": 4242}
        for w in self.subscribers:
            w.write((json.dumps(ev) + "\n").encode())

    def of(self, cmd):
        return [r for r in self.requests if r["cmd"] == cmd]


class HostBridgeTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        os.makedirs(t + "/libexec")
        for name, body in (("citadel-monitor", FAKE_MONITOR), ("citadel-explain", FAKE_EXPLAIN), ("citadel-proxy", "")):
            with open(t + "/libexec/" + name, "w") as f:
                f.write(body)
        self.ticks = t + "/ticks"
        env = {"CITADEL_STATE_DIR": t + "/state", "CITADEL_RUNTIME_DIR": t + "/run", "CITADEL_LIBEXEC": t + "/libexec",
               "CITADEL_HELPER_TRANSPORT": "host", "CITADEL_HOST_SOCKET": t + "/host.sock", "FAKE_TICKS": self.ticks,
               "CITADEL_AGENT_FILE": t + "/agent", "CITADEL_PLUGIN_MARKER": "no-plugin-%d" % os.getpid()}
        self.saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        self.host = FakeHost(t + "/host.sock")
        await self.host.start()
        self.d = Daemon(Paths())
        self.d.prefs["notify"] = False
        self.srv = Server(self.d, self.d.p.socket)
        await self.srv.start()
        await self.d.start()
        self.c = Client(self.d.p.socket)
        await self.c.connect()
        with open(self.ticks, "a") as f:
            f.write(tick([]) + "\n")
        self.assertTrue(await self.c.wait_for(lambda s: s.get("helperVersion") == "1.3.0", 8), "host found and verified")
        self.assertTrue(await self.c.wait_for(lambda s: s.get("ticks", 0) >= 1))
        await self.c.call("setEnforce", True)
        self.assertTrue(await self.c.wait_for(lambda s: s.get("enforceAppliedAt", 0) > 0, 6), "spec applied via the host")
        await asyncio.sleep(2.5)                 # the events connection subscribes

    async def asyncTearDown(self):
        self.c.task.cancel()
        self.c.w.close()
        await self.d.stop()
        await self.srv.stop()
        await self.host.stop()
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    async def wait(self, pred, timeout=5.0):
        end = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < end:
            if pred():
                return True
            await asyncio.sleep(0.05)
        return False

    async def test_spec_is_policies_and_context(self):
        await self.c.call("addRule", {"app": "/usr/bin/curl", "host": "example.com", "action": "deny"})
        self.assertTrue(await self.wait(lambda: any(r["args"]["spec"]["rules"] for r in self.host.of("apply"))))
        spec = self.host.of("apply")[-1]["args"]["spec"]
        self.assertEqual(spec["format"], "citadel-macos-1")
        self.assertEqual(spec["rules"][0]["host"], "example.com")
        self.assertEqual(spec["ctx"]["mode"], "guarded")
        self.assertEqual(spec["gate"], {"default": "allow", "timeout": 90.0})

    async def test_paused_flow_waits_at_the_gate_and_the_answer_resumes_it(self):
        self.host.pause("F1", "/usr/bin/curl", "93.184.216.34", host="example.com")
        self.assertTrue(await self.c.wait_for(lambda s: len(s.get("alerts", [])) == 1), "gate request")
        self.host.pause("F2", "/usr/bin/curl", "93.184.216.34", host="example.com")    # same app+host+port
        await asyncio.sleep(0.5)
        self.assertEqual(len(self.c.state["alerts"]), 1, "one request for both flows")
        await self.c.call("answer", self.c.state["alerts"][0]["key"], "allow", "host", "forever")
        self.assertTrue(await self.wait(lambda: self.host.of("resolve")))
        self.assertEqual(self.host.of("resolve")[0]["args"], {"flows": ["F1", "F2"], "allow": True})

    async def test_a_policy_decides_new_flows_at_once(self):
        await self.c.call("addRule", {"app": "/usr/bin/curl", "host": "blocked.example", "action": "deny"})
        await asyncio.sleep(0.3)
        self.host.pause("F3", "/usr/bin/curl", "203.0.113.9", host="blocked.example")
        self.assertTrue(await self.wait(lambda: self.host.of("resolve")))
        self.assertEqual(self.host.of("resolve")[0]["args"], {"flows": ["F3"], "allow": False})
        self.assertEqual(self.c.state.get("alerts", []), [])

    async def test_a_new_policy_resolves_waiting_flows(self):
        self.host.pause("F4", "/usr/bin/git", "198.51.100.7", host="git.example")
        self.assertTrue(await self.c.wait_for(lambda s: len(s.get("alerts", [])) == 1))
        await self.c.call("addRule", {"app": "/usr/bin/git", "action": "allow"})
        self.assertTrue(await self.wait(lambda: self.host.of("resolve")))
        self.assertEqual(self.host.of("resolve")[0]["args"], {"flows": ["F4"], "allow": True})

    async def test_feeds_go_to_the_extension_once(self):
        r = await self.c.call("importFeed", "Imported (2)", ["ads.example.com", "tracker.example"], "")
        self.assertTrue(r["ok"])
        await self.c.call("setMode", "guarded", 0)            # a sync
        def mine():
            for req in reversed(self.host.of("feeds")):
                hit = [f for f in req["args"]["feeds"] if f["id"] == r["result"]]
                if hit:
                    return hit
            return []
        self.assertTrue(await self.wait(lambda: mine(), 8), "a feeds call with the imported list")
        mine = mine()
        self.assertEqual(mine[0]["entries"], ["ads.example.com", "tracker.example"])
        n = len(self.host.of("feeds"))
        await self.c.call("setMode", "guarded", 0)
        await asyncio.sleep(1.5)
        self.assertEqual(len(self.host.of("feeds")), n, "unchanged feeds are not sent again")

    async def test_off_goes_to_the_host(self):
        await self.c.call("setEnforce", False)
        self.assertTrue(await self.wait(lambda: self.host.of("off")))


if __name__ == "__main__":
    unittest.main()
