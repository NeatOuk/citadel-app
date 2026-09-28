"""Integrity check backends of the Linux monitor (citadel.monitor.linux), with fixture databases."""
import gzip
import hashlib
import os
import runpy
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel.monitor import linux as _linux  # noqa: E402
G = vars(_linux)


class Integrity(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
