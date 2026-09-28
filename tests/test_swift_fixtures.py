"""The Swift parity fixture (macos/.../Fixtures/parity.json) must match what
citadel/model.py answers today; if this fails, run
tests/tools/make_swift_fixtures.py and commit the result."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from tests.tools import make_swift_fixtures as F  # noqa: E402


class SwiftFixture(unittest.TestCase):
    def test_up_to_date(self):
        with open(F.OUT) as f:
            self.assertTrue(f.read() == F.text(), "parity.json is stale: run tests/tools/make_swift_fixtures.py")


if __name__ == "__main__":
    unittest.main()
