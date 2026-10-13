"""citadel.launchers: menu launchers that start routed browsers through Citadel's front door."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel import launchers as L  # noqa: E402

EDGE = """[Desktop Entry]
Name=Microsoft Edge
Exec=%s %%U
Type=Application

[Desktop Action new-private-window]
Name=New InPrivate window
Exec=%s --inprivate
"""


class Launchers(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        opt = os.path.join(self.root, "opt", "msedge")
        os.makedirs(opt)
        self.exe = os.path.join(opt, "msedge")
        wrapper = os.path.join(opt, "microsoft-edge")
        for path in (self.exe, wrapper):
            open(path, "w").close()
        bindir = os.path.join(self.root, "bin")
        os.makedirs(bindir)
        link = os.path.join(bindir, "microsoft-edge-stable")
        os.symlink(wrapper, link)                  # as /usr/bin/microsoft-edge-stable -> /opt/microsoft/msedge/
        self.system = os.path.join(self.root, "share", "applications")
        os.makedirs(self.system)
        with open(os.path.join(self.system, "microsoft-edge.desktop"), "w") as f:
            f.write(EDGE % (link, link))
        with open(os.path.join(self.system, "other.desktop"), "w") as f:
            f.write("[Desktop Entry]\nExec=/usr/bin/true\n")
        saved = {k: os.environ.get(k) for k in ("XDG_DATA_HOME", "XDG_DATA_DIRS")}
        os.environ["XDG_DATA_HOME"] = os.path.join(self.root, "home")
        os.environ["XDG_DATA_DIRS"] = os.path.join(self.root, "share")

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(restore)
        self.mine = os.path.join(self.root, "home", "applications", "microsoft-edge.desktop")

    def read(self):
        with open(self.mine) as f:
            return f.read()

    def test_routed_browser_starts_through_the_front_door(self):
        status = L.sync({self.exe, "/usr/bin/curl"}, 47100)
        self.assertEqual(status, [{"exe": self.exe, "name": "msedge", "file": self.mine, "state": "managed"}])
        text = self.read()
        execs = [l for l in text.splitlines() if l.startswith("Exec=")]
        self.assertEqual(len(execs), 2)
        self.assertTrue(all("microsoft-edge-stable --proxy-server=socks5://127.0.0.1:47100 " in l for l in execs), execs)
        self.assertIn(L.MARK, text)
        L.sync({self.exe}, 47100)                  # idempotent: the flag is added once
        self.assertEqual(self.read(), text)

    def test_unrouted_or_off_removes_only_citadels_launchers(self):
        L.sync({self.exe}, 47100)
        own = os.path.join(os.path.dirname(self.mine), "mine.desktop")
        with open(own, "w") as f:
            f.write("[Desktop Entry]\nExec=/usr/bin/true\n")
        self.assertEqual(L.sync(set(), 47100), [])
        self.assertFalse(os.path.exists(self.mine))
        self.assertTrue(os.path.exists(own))
        L.sync({self.exe}, 47100)
        L.sync({self.exe}, 0)                      # option off / proxy stopped
        self.assertFalse(os.path.exists(self.mine))

    def test_users_own_launcher_is_left_alone(self):
        os.makedirs(os.path.dirname(self.mine))
        with open(self.mine, "w") as f:
            f.write("[Desktop Entry]\nExec=/x/my-edge\n")
        status = L.sync({self.exe}, 47100)
        self.assertEqual(status[0]["state"], "own")
        self.assertEqual(self.read(), "[Desktop Entry]\nExec=/x/my-edge\n")

    def test_quoted_program(self):
        line = 'Exec="/opt/My Browser/brave" --incognito %U'
        self.assertEqual(L.exec_binary(line), "/opt/My Browser/brave")
        self.assertEqual(L.with_flag(line, "--f"), 'Exec="/opt/My Browser/brave" --f --incognito %U')

    def test_which_processes_started_through_it(self):
        self.assertIsNone(L.started_through(2 ** 22 + 7, 47100))           # gone
        self.assertFalse(L.started_through(os.getpid(), 47100))
        self.assertTrue(L.is_browser("/opt/microsoft/msedge/msedge") and not L.is_browser("/usr/bin/curl"))


if __name__ == "__main__":
    unittest.main()
