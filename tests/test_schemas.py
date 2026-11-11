"""Unit tests for result/matrix/bundle schemas (harness.schemas)."""

import pytest
from harness.schemas import (
    BUNDLE_FILES,
    LSM_FUNCS_ROW_KEYS,
    REQUIRED_COUNTER_KEYS,
    SCHEMA_VERSION,
    SIGNATURE_KINDS,
    VERDICT_CLASSIFICATION,
    aggregate_totals,
    aggregate_verdict,
    empty_bundle_metadata,
    empty_matrix,
    empty_result,
    is_fail,
    is_pass,
    is_skip,
    lsm_funcs_row,
)


def test_empty_result_required_fields():
    r = empty_result("c123")
    for key in (
        "schema_version",
        "cell_id",
        "verdict",
        "classifier_hits",
        "perf",
        "artifacts",
        "host",
        "cmdline",
    ):
        assert key in r
    assert r["schema_version"] == SCHEMA_VERSION
    assert r["cell_id"] == "c123"
    # journalctl_kb was renamed to journalctl_log; the old name must not leak.
    assert "journalctl_log" in r["artifacts"]
    assert "journalctl_kb" not in r["artifacts"]


def test_verdict_classification():
    assert is_pass("pass")
    assert is_fail("kernel-bug")
    assert is_skip("skip:no-kvm")
    assert is_skip("skip:stats-unavailable")
    assert not is_pass("kernel-bug")
    assert not is_skip("pass")
    # The bare "stats-unavailable" verdict was renamed; the old form must
    # no longer classify as skip.
    assert not is_skip("stats-unavailable")


def test_normative_classification_table():
    # Every entry in the table must agree with the helper functions, so
    # TAP/KTAP and bisect-run never disagree about a verdict.
    for verdict, klass in VERDICT_CLASSIFICATION.items():
        if klass == "pass":
            assert is_pass(verdict), verdict
        elif klass == "fail":
            assert is_fail(verdict), verdict
        elif klass == "skip":
            assert is_skip(verdict), verdict
        else:
            pytest.fail(f"unknown classification {klass!r} for {verdict!r}")


def test_aggregate_totals():
    cells = [
        {"verdict": "pass"},
        {"verdict": "pass"},
        {"verdict": "kernel-bug"},
        {"verdict": "skip:no-kvm"},
        {"verdict": "skip:stats-unavailable"},
        {"verdict": "aborted"},
        {"verdict": None},  # not yet executed
    ]
    t = aggregate_totals(cells)
    assert t["planned"] == 7
    assert t["executed"] == 6
    assert t["passed"] == 2
    assert t["failed"] == 1
    assert t["skipped"] == 2
    assert t["aborted"] == 1


def test_aggregate_verdict():
    assert aggregate_verdict({"executed": 0}) == "no-cells"
    assert (
        aggregate_verdict({"executed": 3, "passed": 3, "failed": 0, "skipped": 0, "aborted": 0})
        == "pass"
    )
    assert (
        aggregate_verdict({"executed": 3, "passed": 2, "failed": 1, "skipped": 0, "aborted": 0})
        == "fail"
    )
    assert (
        aggregate_verdict({"executed": 2, "passed": 1, "failed": 0, "skipped": 0, "aborted": 1})
        == "fail"
    )
    assert (
        aggregate_verdict({"executed": 4, "passed": 0, "failed": 0, "skipped": 4, "aborted": 0})
        == "skip-all"
    )


def test_empty_matrix_shape():
    m = empty_matrix()
    assert m["schema_version"] == SCHEMA_VERSION
    assert m["totals"]["planned"] == 0


def test_required_counter_keys_cover_ac_5_1():
    # AC-5.1: lvm.{nalloc,nfree,nusage}, lmem.{nalloc,nrealloc,nfree,total,
    # average,minimum,maximum}, kvcache.{nalloc,nfree,nusage}.
    expected = {
        "lvm.nalloc",
        "lvm.nfree",
        "lvm.nusage",
        "lmem.nalloc",
        "lmem.nrealloc",
        "lmem.nfree",
        "lmem.total",
        "lmem.average",
        "lmem.minimum",
        "lmem.maximum",
        "kvcache.nalloc",
        "kvcache.nfree",
        "kvcache.nusage",
    }
    assert set(REQUIRED_COUNTER_KEYS) == expected


def test_lsm_funcs_row_shape():
    row = lsm_funcs_row("file_open", nlsm=1, count=5, total=5000, average=1000, maxtime=2500)
    assert set(row.keys()) == set(LSM_FUNCS_ROW_KEYS)
    assert row["name"] == "file_open"
    assert row["count"] == 5


def test_bundle_metadata_requires_signature_kind():
    m = empty_bundle_metadata("c123", "abc123", "primary")
    assert m["schema_version"] == SCHEMA_VERSION
    assert m["signature_kind"] == "primary"
    assert m["files"] == list(BUNDLE_FILES)

    m2 = empty_bundle_metadata("c123", "abc123", "fallback")
    assert m2["signature_kind"] == "fallback"

    for kind in SIGNATURE_KINDS:
        empty_bundle_metadata("c", "h", kind)  # must not raise

    with pytest.raises(ValueError):
        empty_bundle_metadata("c123", "abc123", "primary-typo")
