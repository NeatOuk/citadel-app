"""The macOS monitor against the real tools. Runs only on a Mac (CI: the
macos job); elsewhere every test is skipped.

It opens a real TCP connection and checks that lsof, ps, KERN_PROCARGS2,
codesign/spctl, netstat and a whole tick through the darwin backend see it.
"""
import json
import os
import socket
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("CITADEL_STATE_DIR", tempfile.mkdtemp(prefix="citadel-live-"))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

ON_MAC = sys.platform == "darwin"
if ON_MAC:
    from citadel.monitor import common, darwin as D  # noqa: E402

TARGET = ("1.1.1.1", 443)


@unittest.skipUnless(ON_MAC, "macOS only")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sock = socket.create_connection(TARGET, timeout=10)
        cls.lport = cls.sock.getsockname()[1]

    @classmethod
    def tearDownClass(cls):
        cls.sock.close()

    def test_lsof_sees_our_connection(self):
        rows = D.parse_lsof(D._text(["lsof", "-nP", "-w", "-i", "-T", "s", "-F", "pcuPnT"]))
        mine = [r for r in rows if r["pid"] == os.getpid() and r["raddr"] == TARGET[0]]
        self.assertTrue(mine, "our connection in lsof: %s" % rows[:5])
        self.assertEqual((mine[0]["rport"], mine[0]["lport"], mine[0]["proto"], mine[0]["state"]),
                         (443, self.lport, "tcp", "ESTABLISHED"))
        self.assertEqual(mine[0]["uid"], os.getuid())

    def test_ps_and_procargs(self):
        D._ps["ts"] = 0
        st = D.proc_stat(os.getpid())
        self.assertIsNotNone(st)
        self.assertEqual(st[1], os.getppid())
        self.assertTrue(D.proc_exe(os.getpid()).startswith("/"))
        args = D.proc_cmdline(os.getpid())
        self.assertTrue(args and "python" in os.path.basename(args[0]).lower(), args)

    def test_signatures_of_apple_programs(self):
        for exe in ("/usr/bin/curl", "/System/Applications/Calculator.app/Contents/MacOS/Calculator"):
            t = D.trust_now(exe)
            self.assertEqual((t["level"], t.get("pkg")), ("verified", "Apple"), exe)

    def test_totals_and_nettop(self):
        rx, tx = D.parse_netstat(D._text(["netstat", "-ibn"]))
        self.assertGreater(rx + tx, 0)
        out = D._text(["nettop", "-L", "1", "-n", "-x", "-J", "bytes_in,bytes_out"], timeout=20)
        flows = [f for f in map(D.parse_nettop_line, out.splitlines()) if f]
        self.assertTrue(flows, out[:500])

    def test_whole_tick(self):
        events = []
        saved = common.emit
        common.emit = events.append
        common.use(D)
        D._lsof_cache["ts"] = D._ps["ts"] = 0

        class Hist:
            def sample(self, *a): pass
            def update(self, *a): pass
            def record_short(self, *a): pass
        try:
            common.tick(Hist(), {}, None)
        finally:
            common.emit = saved
        tick = [e for e in events if e.get("type") == "tick"][-1]
        json.dumps(tick)
        mine = [c for c in tick["conns"] if c["pid"] == os.getpid() and c["raddr"] == TARGET[0]]
        self.assertTrue(mine, [c["raddr"] for c in tick["conns"]])
        self.assertEqual(mine[0]["scope"], "internet")
        self.assertIn(mine[0]["exe"], tick["apps"])


if __name__ == "__main__":
    unittest.main()
