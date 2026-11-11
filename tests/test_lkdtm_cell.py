"""Unit tests for LKDTM verdict adjustment (harness.lkdtm_cell)."""

from harness import lkdtm_cell


def test_provoke_missing_is_skip():
    r = {"verdict": "pass", "classifier_hits": []}
    out = lkdtm_cell.adjust_verdict_for_lkdtm(r, workload_returncode=77)
    assert out["verdict"] == "skip:no-lkdtm"
    assert "CONFIG_LKDTM" in out["reason"]


def test_splat_observed_inverts_to_pass():
    # The regular cell would have classified this as kernel-bug; LKDTM
    # wrapper inverts that to pass since the splat was the desired output.
    r = {
        "verdict": "kernel-bug",
        "classifier_hits": [{"pattern": "BUG: KASAN", "line": 5, "substring": "BUG: KASAN: ..."}],
    }
    out = lkdtm_cell.adjust_verdict_for_lkdtm(r, workload_returncode=0)
    assert out["verdict"] == "pass"
    assert "classifier caught" in out["reason"]


def test_splat_missing_is_failure_of_classifier():
    # No classifier hits despite LKDTM running successfully: classifier
    # likely regressed. Report kernel-bug at the matrix level.
    r = {"verdict": "pass", "classifier_hits": []}
    out = lkdtm_cell.adjust_verdict_for_lkdtm(r, workload_returncode=0)
    assert out["verdict"] == "kernel-bug"
    assert "classifier saw no splat" in out["reason"]
