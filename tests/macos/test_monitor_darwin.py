"""The macOS monitor backend on any OS, with recorded (anonymised) output
of lsof, nettop, ps, netstat, networksetup, ipconfig and codesign.

The full tick runs through citadel.monitor.common with the darwin backend,
so the daemon-facing JSON is checked too.
"""
import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
os.environ.setdefault("CITADEL_STATE_DIR", tempfile.mkdtemp(prefix="citadel-mac-test-"))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from citadel.monitor import common, darwin as D  # noqa: E402


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read().replace("__UID__", str(os.getuid()))


class Parsers(unittest.TestCase):
    def test_lsof(self):
        rows = D.parse_lsof(fixture("lsof.txt"))
        by = {r["raddr"]: r for r in rows}
        self.assertEqual(len(rows), 4, "listening and unconnected sockets are skipped")
        self.assertEqual((by["203.0.113.5"]["comm"], by["203.0.113.5"]["lport"]), ("Safari", 52001))
        self.assertEqual(by["2001:db8:1::5"]["comm"], "Safari")
        self.assertEqual(by["198.51.100.7"]["state"], "SYN_SENT")
        self.assertEqual((by["192.0.2.1"]["proto"], by["192.0.2.1"]["rport"]), ("udp", 53))

    def test_nettop(self):
        got = [D.parse_nettop_line(l) for l in fixture("nettop.txt").splitlines()]
        flows = {g[0]: (g[1], g[2]) for g in got if g}
        self.assertEqual(flows[(52001, "203.0.113.5", 443)], (4000, 1000))
        self.assertEqual(flows[(52002, "2001:db8:1::5", 443)], (1000, 200))
        self.assertEqual(len(flows), 3, "process summary lines are not flows")

    def test_ps(self):
        rows = D.parse_ps(fixture("ps.txt"))
        self.assertEqual(rows[777][0], 460)
        self.assertEqual(rows[501][3], "/Applications/Safari.app/Contents/MacOS/Safari")
        self.assertGreater(rows[777][2], rows[1][2])

    def test_netstat_counts_each_physical_interface_once(self):
        self.assertEqual(D.parse_netstat(fixture("netstat.txt")), (9100000, 1550000))

    def test_networks(self):
        ports = D.parse_hardware_ports(fixture("hardwareports.txt"))
        self.assertIn(("Wi-Fi", "en0"), ports)
        self.assertEqual(D.parse_ssid(fixture("ipconfig-en0.txt")), "Example Cafe")
        self.assertEqual(D.parse_ssid("  SSID : <redacted>\n"), "")

    def test_signatures(self):
        self.assertEqual(D.classify_signature(fixture("codesign-safari.txt"), True, "accepted\nsource=Apple System"),
                         {"level": "verified", "pkg": "Apple"})
        self.assertEqual(D.classify_signature(fixture("codesign-devid.txt"), True, "accepted\nsource=Notarized Developer ID"),
                         {"level": "verified", "pkg": "Example Corp (ABCDE12345)"})
        self.assertEqual(D.classify_signature(fixture("codesign-devid.txt"), True, "rejected")["reason"],
                         "signed by Example Corp (ABCDE12345), not notarized")
        self.assertEqual(D.classify_signature(fixture("codesign-devid.txt"), False, "")["level"], "modified")
        self.assertIn("ad-hoc", D.classify_signature(fixture("codesign-adhoc.txt"), True, "rejected")["reason"])
        self.assertEqual(D.classify_signature("x: code object is not signed at all", False, ""),
                         {"level": "unpackaged", "reason": "unsigned"})
        self.assertEqual(D.bundle_of("/Applications/Safari.app/Contents/MacOS/Safari"), "/Applications/Safari.app")

    def test_procargs(self):
        raw = struct.pack("=i", 3) + b"/usr/bin/curl\0\0\0\0curl\0-s\0https://example.com\0KEY=x\0"
        self.assertEqual(D.parse_procargs(raw), ["curl", "-s", "https://example.com"])


class Tick(unittest.TestCase):
    """The whole tick with the darwin backend, commands answered from fixtures."""

    def setUp(self):
        answers = {"lsof": fixture("lsof.txt"), "ps": fixture("ps.txt"), "netstat": fixture("netstat.txt"),
                   "networksetup": fixture("hardwareports.txt"), "ipconfig": fixture("ipconfig-en0.txt"),
                   "ifconfig": "status: inactive\n", "codesign": fixture("codesign-safari.txt")}
        self._text = D._text
        D._text = lambda cmd, timeout=10: answers.get(cmd[0], "")
        D._lsof_cache["ts"] = D._ps["ts"] = D.net_state["ts"] = 0
        D._nettop["flows"] = {g[0]: (g[1], g[2]) for g in map(D.parse_nettop_line, fixture("nettop.txt").splitlines()) if g}
        D.proc_cmdline = lambda pid: {777: ["curl", "-s", "-H", "Authorization: Bearer abc", "https://example.com"]}.get(pid, [])
        self.events = []
        self._emit = common.emit
        common.emit = self.events.append
        common.use(D)

    def tearDown(self):
        D._text = self._text
        common.emit = self._emit

    def test_tick(self):
        class Hist:
            def sample(self, *a): pass
            def update(self, *a): pass
            def record_short(self, *a): pass
        common.tick(Hist(), {}, None)
        tick = [e for e in self.events if e.get("type") == "tick"][-1]
        json.dumps(tick)                                      # the daemon must be able to read it
        conns = {c["raddr"]: c for c in tick["conns"]}
        self.assertEqual(set(conns), {"203.0.113.5", "2001:db8:1::5", "198.51.100.7", "192.0.2.1"})
        s = conns["203.0.113.5"]
        self.assertEqual((s["app"], s["exe"], s["down"], s["up"], s["cgroup"]),
                         ("Safari", "/Applications/Safari.app/Contents/MacOS/Safari", 4000, 1000, ""))
        self.assertEqual((conns["2001:db8:1::5"]["down"], conns["2001:db8:1::5"]["up"]), (1000, 200))
        self.assertEqual(conns["192.0.2.1"]["scope"], "lan")
        c = conns["198.51.100.7"]
        self.assertEqual(c["state"], "syn-sent")
        self.assertEqual(c["via"], "Terminal", "started in the terminal")
        self.assertEqual(c["viaKind"], "terminal")
        self.assertNotIn("abc", c["cmd"], "secrets in the command line are masked")
        self.assertEqual(tick["network"]["names"], ["Example Cafe"])
        self.assertEqual(tick["totals"], {"rx": 9100000, "tx": 1550000})
        # the signature levels are covered by test_signatures; here the file
        # only exists on a Mac, so off a Mac the level is "unknown"
        trust = tick["apps"]["/Applications/Safari.app/Contents/MacOS/Safari"]["trust"]
        self.assertIn(trust["level"], ("verified", "unknown"))


if __name__ == "__main__":
    unittest.main()
