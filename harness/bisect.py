"""Bisect-run mode: convert per-cell or matrix verdict to KSFT exit code.

`git bisect run` expects:
    0       good (test passed)
    1..124  bad (test failed) - any non-zero non-skip non-abort
    125     skip (untestable commit; bisect retries elsewhere)
    128+    abort (unrecoverable; bisect halts)

Two callers exist:

* Single-cell `bisect-run --cell <profile>`: maps the cell's verdict directly
  via `exit_code_from_cell_result()`. Build/boot/no-KVM/stats-unavailable/
  image-not-warm collapse to 125 (commit untestable). Bundle-write failure or
  any unhandled harness exception is 128.

* Matrix `bisect-run --config <matrix>`: maps the aggregate via
  `exit_code_from_matrix()` (back-compat). A non-empty matrix with a mix of
  skip+pass is "pass" (we've gathered enough signal). Only when EVERY
  executed cell skipped do we tell bisect to skip.

The mappings are pure functions over dicts so callers can unit-test them
without spinning up a real matrix run.
"""

from __future__ import annotations

from collections.abc import Mapping

from . import schemas

KSFT_PASS = 0
KSFT_FAIL = 1
KSFT_SKIP = 125
KSFT_ABORT = 128


# Per-cell verdicts that mean "the commit cannot be tested" (skip-and-continue
# the bisect). build-fail and boot-timeout are listed by `schemas.FAIL_VERDICTS`
# as fail-class for TAP, but for `git bisect run` we want them treated as skip
# because the commit itself never produced a kernel signal worth blaming.
_CELL_UNTESTABLE_VERDICTS: frozenset[str] = frozenset(
    {
        "build-fail",
        "boot-timeout",
    }
)

# Per-cell verdicts that mean "the harness itself broke" (abort the bisect).
# Bundle-write failures are detected separately via `result.get("bundle_error")`
# and ALSO route here.
_CELL_ABORT_VERDICTS: frozenset[str] = frozenset(
    {
        "harness-error",
        "aborted",
        "no-dmesg",
    }
)


def exit_code_from_cell_result(result: Mapping[str, object]) -> int:
    """Map a single-cell result.json dict to a `git bisect run` exit code.

    Precedence (highest first):
    1. Bundle-write failure (`result["bundle_error"]` present): 128 (abort).
       A cell that produced a real splat but failed to package the
       reproducer cannot give bisect a trustworthy answer.
    2. Harness-internal failure verdicts (`harness-error`, `aborted`,
       `no-dmesg`): 128 (abort).
    3. Untestable-commit verdicts (`build-fail`, `boot-timeout`) and any
       `skip:*` verdict: 125 (skip-and-continue).
    4. Pass verdict: 0.
    5. Any other fail verdict (`kernel-bug`, `workload-fail`): 1 (bad).

    A missing verdict is treated as abort so bisect halts rather than
    silently blaming the commit.
    """
    if result.get("bundle_error"):
        return KSFT_ABORT
    verdict = result.get("verdict")
    if not isinstance(verdict, str):
        return KSFT_ABORT
    if verdict in _CELL_ABORT_VERDICTS:
        return KSFT_ABORT
    if verdict in _CELL_UNTESTABLE_VERDICTS:
        return KSFT_SKIP
    if schemas.is_skip(verdict):
        return KSFT_SKIP
    if schemas.is_pass(verdict):
        return KSFT_PASS
    if schemas.is_fail(verdict):
        return KSFT_FAIL
    return KSFT_ABORT


def exit_code_from_totals(totals: Mapping[str, int]) -> int:
    verdict = schemas.aggregate_verdict(totals)
    if verdict == "pass":
        return KSFT_PASS
    if verdict == "fail":
        return KSFT_FAIL
    if verdict == "skip-all":
        return KSFT_SKIP
    if verdict == "no-cells":
        return KSFT_ABORT
    # Defensive: an unrecognised verdict should abort bisect rather than be
    # silently treated as pass/fail.
    return KSFT_ABORT


def exit_code_from_matrix(matrix: Mapping[str, object]) -> int:
    totals = matrix.get("totals") or {}
    if not isinstance(totals, dict):
        return KSFT_ABORT
    return exit_code_from_totals(totals)
