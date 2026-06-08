"""LKDTM positive-control cell wrapper.

The LKDTM cell exists to verify the harness's classifier itself: on a kernel
with CONFIG_LKDTM=y, writing "WARNING" to /sys/kernel/debug/provoke-crash/DIRECT
produces a real splat. If the regular cell-level classifier classifies it
correctly as kernel-bug, that is positive proof the splat-detection pipe is
working. The matrix-level wrapper here flips that verdict so an LKDTM cell
"passes" when classifier saw the splat, and "fails" when it didn't.

If CONFIG_LKDTM was not built, the workload returns return-code 77 and we
report skip:no-lkdtm (a SKIP-class verdict; this kernel can't run the
positive control, but the rest of the matrix is still meaningful).
"""

from __future__ import annotations

from typing import Any

LKDTM_PROVOKE_RC = 77  # by convention, matches the workload short-circuit


def adjust_verdict_for_lkdtm(result: dict[str, Any], workload_returncode: int | None) -> dict[str, Any]:
    """Invert the cell's verdict for LKDTM positive-control semantics.

    Parameters:
        result: the run_cell() result dict (possibly with verdict already set).
        workload_returncode: the LKDTM workload's exit code; 77 means the
            provoke-crash node was missing (no CONFIG_LKDTM).

    Returns the same dict for chaining; mutates verdict + reason.
    """
    if workload_returncode == LKDTM_PROVOKE_RC:
        result["verdict"] = "skip:no-lkdtm"
        result["reason"] = "LKDTM provoke node missing (CONFIG_LKDTM not enabled)"
        return result

    classifier_saw_splat = bool(result.get("classifier_hits"))
    if classifier_saw_splat:
        # Splat present, classifier picked it up: positive control worked.
        result["verdict"] = "pass"
        result["reason"] = "LKDTM splat observed; classifier caught the positive control"
    else:
        # Splat expected but absent: classifier missed it (or LKDTM no-op'd).
        result["verdict"] = "kernel-bug"
        result["reason"] = (
            "LKDTM provoke ran but classifier saw no splat; possible classifier regression"
        )
    return result
