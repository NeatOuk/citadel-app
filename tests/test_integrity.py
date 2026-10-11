"""Integrity check backends of the Linux monitor (citadel.monitor.linux), with fixture databases."""
import gzip
import hashlib
import os
import runpy
import sys
import tempfile
import time
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel.monitor import common as C  # noqa: E402
from citadel.monitor import linux as _linux  # noqa: E402
G = vars(_linux)


class Integrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._saved = (C.DIGESTS, C.digests)
        C.DIGESTS, C.digests = os.path.join(self.tmp.name, "digests.json"), None
        self.addCleanup(lambda: setattr(C, "DIGESTS", self._saved[0]) or setattr(C, "digests", self._saved[1]))

    def test_merged_usr_aliases(self):
        self.assertIn("/bin/curl", G["_alt_paths"]("/usr/bin/curl"))
        self.assertIn("/usr/lib/x.so", G["_alt_paths"]("/lib/x.so"))

    def test_dpkg_md5sums(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "curl.md5sums"), "w") as f:
                f.write("0123456789abcdef0123456789abcdef  usr/bin/curl\n" "ffffffffffffffffffffffffffffffff  usr/share/doc/x\n")
            with open(os.path.join(d, "libc6:amd64.md5sums"), "w") as f:
                f.write("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lib/x86_64-linux-gnu/libc.so.6\n")
            self.assertEqual(G["dpkg_digest"]("curl", "/usr/bin/curl", d), ("md5", "0123456789abcdef0123456789abcdef"))
            self.assertEqual(G["dpkg_digest"]("curl", "/bin/curl", d), ("md5", "0123456789abcdef0123456789abcdef"))
            self.assertEqual(G["dpkg_digest"]("libc6", "/usr/lib/x86_64-linux-gnu/libc.so.6", d)[1], "a" * 32)
            self.assertIsNone(G["dpkg_digest"]("curl", "/usr/bin/wget", d))

    def test_rpm_digests(self):
        text = "8\n/usr/bin/curl\tabc123\n/usr/share/man/curl.1.gz\tdef\n"
        self.assertEqual(G["parse_rpm_digests"](text, "/usr/bin/curl"), ("sha256", "abc123"))
        self.assertEqual(G["parse_rpm_digests"]("1\n/bin/ls\t00ff\n", "/usr/bin/ls"), ("md5", "00ff"))
        self.assertIsNone(G["parse_rpm_digests"]("", "/usr/bin/curl"))

    def test_pacman_mtree(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "curl-8.0-1"))
            with open(os.path.join(d, "curl-8.0-1", "desc"), "w") as f:
                f.write("%NAME%\ncurl\n")
            digest = "b" * 64
            with gzip.open(os.path.join(d, "curl-8.0-1", "mtree"), "wt") as f:
                f.write("./usr/bin/curl time=1 mode=755 sha256digest=%s\n" % digest)
            self.assertEqual(G["mtree_digest"]("curl", "/usr/bin/curl", d), ("sha256", digest))

    def test_file_digest(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"hello")
            f.flush()
            self.assertEqual(G["file_digest"](f.name, "md5"), hashlib.md5(b"hello").hexdigest())

    def test_trim_keeps_newest(self):
        d = {i: i for i in range(101)}
        C.trim(d, 100)
        self.assertLessEqual(len(d), 100)
        self.assertIn(100, d)
        self.assertNotIn(0, d)

    def test_digests_persist_for_root_owned_files_only(self):
        root_file = os.path.realpath("/usr/bin/true")
        if os.stat(root_file).st_uid != 0:
            self.skipTest("no root-owned /usr/bin/true")
        with open(root_file, "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()
        mine = os.path.join(self.tmp.name, "prog")
        with open(mine, "wb") as f:
            f.write(b"one")
        self.assertEqual(C.sha256(root_file), want)
        self.assertEqual(C.sha256(mine), hashlib.sha256(b"one").hexdigest())
        C.save_digests(force=True)
        C.digests = None                               # as after a restart
        self.assertEqual(len(C._digests()), 1)         # the user's own file is never stored
        real_open, reads = open, []

        def counting_open(p, *a, **k):
            reads.append(p)
            return real_open(p, *a, **k)
        with unittest.mock.patch("builtins.open", counting_open):
            self.assertEqual(C.sha256(root_file), want)
        self.assertNotIn(root_file, reads)             # served from digests.json
        self.assertEqual(os.stat(C.DIGESTS).st_mode & 0o777, 0o600)

    def test_trust_checks_in_the_background(self):
        d = tempfile.TemporaryDirectory(dir=HERE)     # not /tmp: that is "suspicious"
        self.addCleanup(d.cleanup)
        exe = os.path.join(d.name, "tool")
        with open(exe, "wb") as f:
            f.write(b"bin")
        with unittest.mock.patch.object(_linux, "pkg_owner", return_value=""):
            first = _linux.trust(exe)
            self.assertEqual(first["reason"], "checking the package")
            self.assertEqual(first["hash"], hashlib.sha256(b"bin").hexdigest())   # pinned rules need it at once
            for _ in range(100):
                t = _linux.trust(exe)
                if t["level"] != "unknown":
                    break
                time.sleep(0.02)
            self.assertEqual(t["level"], "unpackaged")
            self.assertEqual(_linux.trust_now(exe), t)


if __name__ == "__main__":
    unittest.main()
