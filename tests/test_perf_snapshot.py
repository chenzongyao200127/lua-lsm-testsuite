"""Unit tests for perf stat snapshots and validation (harness.perf_snapshot)."""

from harness import perf_snapshot as ps
from harness import schemas
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


def test_parse_stats():
    d = parse_stats_text(SAMPLE_STATS)
    assert d["lvm.nalloc"] == 120
    assert d["lmem.maximum"] == 65536
    assert d["kvcache.nusage"] == 50


def test_parse_lsm_funcs():
    d = parse_lsm_funcs_text(SAMPLE_FUNCS)
    assert set(d.keys()) == {"file_post_open", "task_alloc", "file_open"}
    assert d["file_open"]["count"] == 5
    assert d["file_open"]["maxtime"] == 2500


def test_read_snapshot_returns_none_when_both_absent(tmp_path):
    assert read_snapshot(tmp_path / "no", tmp_path / "no2") is None


def test_read_snapshot_partial_ok(tmp_path):
    stats = tmp_path / "stats"
    stats.write_text(SAMPLE_STATS)
    snap = read_snapshot(stats, tmp_path / "missing")
    assert snap is not None
    assert snap.counters["lvm.nusage"] == 30
    assert snap.lsm_funcs == {}


def test_diff_counters_and_funcs():
    before = Snapshot(
        counters={"lvm.nalloc": 100, "kvcache.nusage": 10},
        lsm_funcs={"file_open": {"nlsm": 1, "count": 0, "total": 0, "average": 0, "maxtime": 0}},
    )
    after = Snapshot(
        counters={"lvm.nalloc": 130, "kvcache.nusage": 12},
        lsm_funcs={
            "file_open": {
                "nlsm": 1,
                "count": 5,
                "total": 5000,
                "average": 1000,
                "maxtime": 2500,
            }
        },
    )
    d = diff(before, after)
    assert d["counters"]["lvm.nalloc"] == 30
    assert d["counters"]["kvcache.nusage"] == 2
    assert d["lsm_funcs"]["file_open"]["count"] == 5
    assert d["lsm_funcs"]["file_open"]["total"] == 5000
    assert d["lsm_funcs"]["file_open"]["maxtime"] == 2500


def test_skip_payload_shape():
    p = stats_available_skip_payload()
    assert p["verdict"] == "skip:stats-unavailable"
    assert p["perf"]["snapshots"] is None


# ---------------------------------------------------------------------------
# Moved from tests/test_round2.py (round-2 dissolution), now pytest-style.
# ---------------------------------------------------------------------------


def _required_counters_text() -> str:
    return "\n".join(f"{k} = {i}" for i, k in enumerate(schemas.REQUIRED_COUNTER_KEYS)) + "\n"


def _valid_funcs_text() -> str:
    return (
        "stats for lua-lsm (ns)\n"
        "num name                         nlsm        "
        "count           total    average      maxtime\n"
        "----\n"
        "  1 inode_permission             1           5               500      100         200\n"
    )


def _snapshot_with(counters, funcs):
    snap = ps.Snapshot()
    snap.counters = counters
    snap.lsm_funcs = funcs
    return snap


def test_validate_snapshot_accepts_valid():
    snap = _snapshot_with(
        ps.parse_stats_text(_required_counters_text()),
        ps.parse_lsm_funcs_text(_valid_funcs_text()),
    )
    assert ps.validate_snapshot(snap) is None


def test_validate_snapshot_rejects_missing_keys():
    snap = _snapshot_with({"lvm.nalloc": 0}, ps.parse_lsm_funcs_text(_valid_funcs_text()))
    reason = ps.validate_snapshot(snap)
    assert reason is not None
    assert "missing required counters" in reason


def test_validate_snapshot_rejects_empty_lsm_funcs():
    snap = _snapshot_with(ps.parse_stats_text(_required_counters_text()), {})
    reason = ps.validate_snapshot(snap)
    assert reason is not None
    assert "lsm_funcs" in reason


def test_validate_snapshot_rejects_none():
    assert ps.validate_snapshot(None) is not None
