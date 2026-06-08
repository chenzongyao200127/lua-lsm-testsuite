import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness.perf_snapshot import (
    Snapshot,
    diff,
    parse_lsm_funcs_text,
    parse_stats_text,
    read_snapshot,
    stats_available_skip_payload,
)

SAMPLE_STATS = """\
lvm.nalloc      =          120
lvm.nfree       =           90
lvm.nusage      =           30
lmem.nalloc     =         5000
lmem.nrealloc   =          400
lmem.nfree      =         4900
lmem.total      =       102400
lmem.average    =         3413
lmem.minimum    =          128
lmem.maximum    =        65536
kvcache.nalloc  =          200
kvcache.nfree   =          150
kvcache.nusage  =           50
"""

SAMPLE_FUNCS = """\
stats for lua-lsm (ns)
num name                         nlsm        count           total    average      maxtime
----
  1 file_post_open                  1            0               0          0            0
  2 task_alloc                      2            0               0          0            0
  3 file_open                       1            5            5000       1000         2500
"""


class ParseTests(unittest.TestCase):
    def test_parse_stats(self):
        d = parse_stats_text(SAMPLE_STATS)
        self.assertEqual(d["lvm.nalloc"], 120)
        self.assertEqual(d["lmem.maximum"], 65536)
        self.assertEqual(d["kvcache.nusage"], 50)

    def test_parse_lsm_funcs(self):
        d = parse_lsm_funcs_text(SAMPLE_FUNCS)
        self.assertEqual(set(d.keys()), {"file_post_open", "task_alloc", "file_open"})
        self.assertEqual(d["file_open"]["count"], 5)
        self.assertEqual(d["file_open"]["maxtime"], 2500)

    def test_read_snapshot_returns_none_when_both_absent(self):
        with TemporaryDirectory() as td:
            self.assertIsNone(read_snapshot(Path(td) / "no", Path(td) / "no2"))

    def test_read_snapshot_partial_ok(self):
        with TemporaryDirectory() as td:
            stats = Path(td) / "stats"
            stats.write_text(SAMPLE_STATS)
            snap = read_snapshot(stats, Path(td) / "missing")
            self.assertIsNotNone(snap)
            self.assertEqual(snap.counters["lvm.nusage"], 30)
            self.assertEqual(snap.lsm_funcs, {})

    def test_diff_counters_and_funcs(self):
        before = Snapshot(
            counters={"lvm.nalloc": 100, "kvcache.nusage": 10},
            lsm_funcs={"file_open": {"nlsm": 1, "count": 0, "total": 0, "average": 0, "maxtime": 0}},
        )
        after = Snapshot(
            counters={"lvm.nalloc": 130, "kvcache.nusage": 12},
            lsm_funcs={"file_open": {"nlsm": 1, "count": 5, "total": 5000, "average": 1000, "maxtime": 2500}},
        )
        d = diff(before, after)
        self.assertEqual(d["counters"]["lvm.nalloc"], 30)
        self.assertEqual(d["counters"]["kvcache.nusage"], 2)
        self.assertEqual(d["lsm_funcs"]["file_open"]["count"], 5)
        self.assertEqual(d["lsm_funcs"]["file_open"]["total"], 5000)
        self.assertEqual(d["lsm_funcs"]["file_open"]["maxtime"], 2500)

    def test_skip_payload_shape(self):
        p = stats_available_skip_payload()
        self.assertEqual(p["verdict"], "skip:stats-unavailable")
        self.assertEqual(p["perf"]["snapshots"], None)


if __name__ == "__main__":
    unittest.main()
