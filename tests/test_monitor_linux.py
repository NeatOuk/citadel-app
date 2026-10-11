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

    def test_last_pid_moves(self):
        from citadel.monitor import linux as L
        before = L.last_pid()
        subprocess.run(["true"])
        self.assertGreater(L.last_pid(), before)


if __name__ == "__main__":
    unittest.main()
