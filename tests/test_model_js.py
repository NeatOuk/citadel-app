"""Runs the plugin's Model.js unit tests (tests/js/model.test.js) under node.

With tests/test_parity.py this covers citadel/model.py too: parity proves the
Python port answers exactly like Model.js.
"""
import os
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


@unittest.skipUnless(shutil.which("node"), "node not installed")
class ModelJs(unittest.TestCase):
    def test_model_js(self):
        p = subprocess.run(["node", os.path.join(HERE, "js", "model.test.js")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
