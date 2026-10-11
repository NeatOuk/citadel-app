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


if __name__ == "__main__":
    unittest.main()
