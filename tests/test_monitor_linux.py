"""Process discovery of the Linux monitor (citadel.monitor.linux)."""
import os
import subprocess
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))


@unittest.skipUnless(sys.platform.startswith("linux"), "reads /proc")
class ProcessWatcher(unittest.TestCase):
    def test_new_pids_finds_processes_not_threads(self):
        from citadel.monitor import linux as L
        before = L.last_pid()
        stop = threading.Event()
        t = threading.Thread(target=stop.wait)
        t.start()
        child = subprocess.Popen(["sleep", "5"])
        try:
            found = L.new_pids(before, L.last_pid())
            self.assertIn(child.pid, found)
            self.assertNotIn(t.native_id, found)
        finally:
            child.kill()
            child.wait()
            stop.set()
            t.join()

    def test_socket_owner_found_and_cached(self):
        import socket
        from citadel.monitor import linux as L
        a, b = socket.socketpair()                 # stands in for an ss row of this process
        try:
            ino = os.fstat(a.fileno()).st_ino
            with open("/proc/self/cgroup") as f:
                cg = f.read().strip().split("::", 1)[1]
            row = {"uid": os.getuid(), "ino": ino, "cgroup": cg, "pid": 0, "comm": ""}
            L.resolve_owners([row])
            self.assertEqual(row["pid"], os.getpid())
            self.assertEqual(L.sock_owner[ino][0], os.getpid())
            moved = dict(row, pid=0, comm="", cgroup="/no/such.scope")   # cache hit, no lookup
            L.resolve_owners([moved])
            self.assertEqual(moved["pid"], os.getpid())
            L.resolve_owners([])                  # gone from ss: dropped from the cache
            self.assertNotIn(ino, L.sock_owner)
        finally:
            a.close()
            b.close()

    @unittest.skipUnless(subprocess.run(["which", "ss"], capture_output=True).returncode == 0, "needs ss")
    def test_match_names_a_connection_by_the_host_the_app_asked_for(self):
        import socket
        from citadel.monitor import common as C
        from citadel.monitor import linux
        saved_backend = C.B
        C.use(linux)
        self.addCleanup(C.use, saved_backend)
        srv = socket.create_server(("127.0.0.1", 0))
        cli = socket.create_connection(srv.getsockname())
        saved = C.lists_state["domains"]
        C.lists_state["domains"] = {"testfeed": {"blocked.example"}}
        try:
            lport, rport = cli.getsockname()[1], srv.getsockname()[1]
            c = C.match_conn(lport, "127.0.0.1", rport, "blocked.example")
            self.assertEqual((c["pid"], c["lport"], c["rport"]), (os.getpid(), lport, rport))
            self.assertEqual((c["host"], c["list"], c["new"]), ("blocked.example", "testfeed", True))
            self.assertEqual(c["exe"], os.path.realpath(sys.executable))
            self.assertIsNone(C.match_conn(lport, "127.0.0.1", rport + 1, "blocked.example"))
        finally:
            C.lists_state["domains"] = saved
            cli.close()
            srv.close()

    def test_last_pid_moves(self):
        from citadel.monitor import linux as L
        before = L.last_pid()
        subprocess.run(["true"])
        self.assertGreater(L.last_pid(), before)

    def test_remember_keeps_only_what_attribution_uses(self):
        import time
        from citadel.monitor import common as C, linux as L
        C.use(L)
        quiet = subprocess.Popen(["sleep", "5"])                       # can't open a connection
        net = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)", "--flag"])
        try:
            time.sleep(0.2)                                            # let both exec
            L.remember(quiet.pid, time.time())
            L.remember(net.pid, time.time())
            self.assertNotIn(quiet.pid, C.proc_seen)                   # attribute() would skip it anyway
            rec = C.proc_seen[net.pid]
            self.assertEqual(rec["args"], [])                          # not a script: args never read
            self.assertNotIn("kind", rec)
            self.assertTrue(any(k[0] == net.pid for k in C.origin_cache))
        finally:
            for p in (quiet, net):
                p.kill()
                p.wait()
        L.forget({net.pid}, time.time())
        self.assertIsNotNone(C.proc_seen[net.pid]["end"])
        self.assertFalse(any(k[0] == net.pid for k in C.origin_cache))  # dead pid: origin dropped
        L.forget(set(), time.time() + 181)
        self.assertNotIn(net.pid, C.proc_seen)


if __name__ == "__main__":
    unittest.main()
