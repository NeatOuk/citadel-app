"""Host names from the names apps look up (systemd-resolved's query monitor),
against a fake resolver socket: learned when allowed, reverse DNS when refused.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel.monitor import common as C  # noqa: E402

# a real query result (systemd 261), shortened
RESULT = {"state": "success",
          "question": [{"class": 1, "type": 1, "name": "api.example.com"}, {"class": 1, "type": 28, "name": "api.example.com"}],
          "answer": [{"rr": {"key": {"class": 1, "type": 5, "name": "api.example.com"}, "name": "edge.cdn.example"}},
                     {"rr": {"key": {"class": 1, "type": 1, "name": "edge.cdn.example"}, "address": [203, 0, 113, 7]}},
                     {"rr": {"key": {"class": 1, "type": 28, "name": "edge.cdn.example"},
                             "address": [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]}}]}


class FakeResolver:
    """Answers SubscribeQueryResults like systemd-resolved: an error, or a stream."""
    def __init__(self, path, refuse):
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(4)
        self.refuse = refuse
        self.requests = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            req = c.recv(4096)
            self.requests.append(json.loads(req.rstrip(b"\0")))
            if self.refuse:
                c.sendall(json.dumps({"error": "io.systemd.InteractiveAuthenticationRequired"}).encode() + b"\0")
                c.close()
                continue
            c.sendall(json.dumps({"parameters": {"state": "success", "question": [], "answer": []}, "continues": True}).encode() + b"\0")
            c.sendall(json.dumps({"parameters": RESULT, "continues": True}).encode() + b"\0")


class DnsNames(unittest.TestCase):
    def setUp(self):
        C.dns_names.clear()
        C.dns_state.update(state="off", error="", seen=0)

    def test_answers_map_to_the_name_that_was_asked(self):
        self.assertEqual(C.learn_names(RESULT), 2)
        self.assertEqual(C.dns_name("203.0.113.7"), "api.example.com")
        self.assertEqual(C.dns_name("2001:db8::7"), "api.example.com")
        self.assertIsNone(C.dns_name("198.51.100.1"))

    def test_failures_and_old_answers_teach_nothing(self):
        self.assertEqual(C.learn_names(dict(RESULT, state="rcode-failure")), 0)
        C.learn_names(RESULT)
        C.dns_names["203.0.113.7"][1] -= 2 * 86400
        self.assertIsNone(C.dns_name("203.0.113.7"))

    def test_a_connection_keeps_its_first_name(self):
        C.learn_names(RESULT)
        self.assertEqual(C.host_name("203.0.113.7", "first.example"), "first.example")
        self.assertEqual(C.host_name("203.0.113.7"), "api.example.com")

    def _follow(self, refuse):
        from citadel.monitor import linux as L
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "monitor")
        fake = FakeResolver(path, refuse)
        self.addCleanup(fake.srv.close)
        saved = L.RESOLVE_MONITOR
        L.RESOLVE_MONITOR = path
        self.addCleanup(setattr, L, "RESOLVE_MONITOR", saved)
        threading.Thread(target=L.dns_follower, daemon=True).start()
        end = time.time() + 3
        while time.time() < end and C.dns_state["state"] == "off":
            time.sleep(0.02)
        time.sleep(0.1)
        return fake

    @unittest.skipUnless(sys.platform.startswith("linux"), "systemd-resolved is Linux")
    def test_follows_the_resolver(self):
        fake = self._follow(refuse=False)
        self.assertEqual(C.dns_state["state"], "on")
        self.assertEqual(C.dns_name("203.0.113.7"), "api.example.com")
        # never asks for a password (no allowInteractiveAuthentication)
        self.assertEqual(fake.requests[0], {"method": "io.systemd.Resolve.Monitor.SubscribeQueryResults", "more": True})

    @unittest.skipUnless(sys.platform.startswith("linux"), "systemd-resolved is Linux")
    def test_refused_without_the_permission(self):
        self._follow(refuse=True)
        self.assertEqual(C.dns_state["state"], "denied")
        self.assertEqual(C.dns_names, {})


if __name__ == "__main__":
    unittest.main()
