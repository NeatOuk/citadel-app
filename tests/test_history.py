"""The monitor's history database: one month in history.db, past months archived as history-YYYYMM.db."""
import os
import sqlite3
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel.monitor import common as C  # noqa: E402

OCT = time.mktime((2026, 10, 13, 12, 0, 0, 0, 0, -1))
NOV = time.mktime((2026, 11, 1, 0, 0, 5, 0, 0, -1))
FLOW = {"key": "k", "proto": "tcp", "raddr": "1.1.1.1", "rport": 443, "up": 1, "down": 2, "app": "curl"}


class Rotation(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        saved = (C.STATE, C.HISTORY_DB)
        C.STATE, C.HISTORY_DB = tmp.name, os.path.join(tmp.name, "history.db")
        self.addCleanup(lambda: (setattr(C, "STATE", saved[0]), setattr(C, "HISTORY_DB", saved[1])))
        self.dir = tmp.name

    def flows(self, path):
        db = sqlite3.connect(path)
        try:
            return db.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        finally:
            db.close()

    def history(self, month):
        h = C.History()
        h.db.execute("UPDATE meta SET v=? WHERE k='month'", (month,))
        h.month = month
        return h

    def test_new_month_archives_the_last_and_starts_fresh(self):
        h = self.history("202610")
        h.update([FLOW], OCT)
        self.assertIsNone(h.rotate(OCT))                       # same month: nothing
        done = h.rotate(NOV)
        archive = os.path.join(self.dir, "history-202610.db")
        self.assertEqual(done, {"file": archive, "month": "202610", "flows": 1})
        self.assertEqual(self.flows(archive), 1)
        self.assertEqual(h.month, "202611")
        h.update([dict(FLOW, key="k2")], NOV)                  # keeps recording, into the new file
        self.assertEqual(self.flows(C.HISTORY_DB), 1)
        self.assertEqual(self.flows(archive), 1)
        self.assertIsNone(h.rotate(NOV + 60))
        h.db.close()

    def test_an_archive_is_never_overwritten(self):
        open(os.path.join(self.dir, "history-202610.db"), "w").close()
        h = self.history("202610")
        self.assertTrue(h.rotate(NOV)["file"].endswith("history-202610-2.db"))
        self.assertEqual(os.path.getsize(os.path.join(self.dir, "history-202610.db")), 0)
        h.db.close()

    def test_an_existing_database_starts_counting_this_month(self):
        db = sqlite3.connect(C.HISTORY_DB)                     # one from before monthly archives
        db.execute("CREATE TABLE flows (id INTEGER PRIMARY KEY, start REAL, last REAL, exe TEXT, comm TEXT,"
                   " proto TEXT, raddr TEXT, rport INTEGER, host TEXT, cc TEXT, up INTEGER, down INTEGER,"
                   " system INTEGER, via TEXT)")
        db.commit()
        db.close()
        h = C.History()
        self.assertEqual(h.month, C.month_of(time.time()))
        self.assertIsNone(h.rotate(time.time()))
        h.db.close()


if __name__ == "__main__":
    unittest.main()
