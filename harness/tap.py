"""Emit TAP/KTAP version 13 from a matrix.json document.

One TAP test point per cell, ordered by `cell_id`. The classification table
in harness.schemas.VERDICT_CLASSIFICATION is normative: a verdict that maps
to "pass" emits "ok", "fail" emits "not ok", and "skip" emits "ok N - cell #
SKIP <reason>". This keeps TAP output consistent with bisect-run mode (both
consume the same classification helpers).

Output format (TAP 13 with plan line LAST per the spec):
    TAP version 13
    ok 1 - <cell_id>
    not ok 2 - <cell_id>
        # verdict: <verdict>
    ok 3 - <cell_id> # SKIP <reason>
    ...
    1..<N>
"""

from __future__ import annotations

from typing import Iterable, Mapping

from . import schemas


def _verdict_class(verdict: str | None) -> str:
    if verdict is None:
        # An unrun cell is reported as not-ok so a run interrupted before
        # completion shows up loud rather than silently passing.
        return "fail"
    return schemas.VERDICT_CLASSIFICATION.get(verdict, "fail")


def emit_tap(matrix: Mapping[str, object]) -> str:
    cells: Iterable[Mapping[str, object]] = matrix.get("cells") or []  # type: ignore[assignment]
    cells = sorted(cells, key=lambda c: str(c.get("cell_id", "")))
    cells = list(cells)

    # Plan line is emitted LAST per TAP 13 trailing-plan convention; consumers
    # that stream output incrementally need the test points before the plan.
    lines: list[str] = ["TAP version 13"]

    for i, cell in enumerate(cells, start=1):
        cell_id = str(cell.get("cell_id", f"cell-{i}"))
        verdict = cell.get("verdict") if isinstance(cell.get("verdict"), str) else None
        klass = _verdict_class(verdict)
        if klass == "pass":
            lines.append(f"ok {i} - {cell_id}")
        elif klass == "skip":
            reason = str(verdict) if verdict else "unknown"
            lines.append(f"ok {i} - {cell_id} # SKIP {reason}")
        else:
            lines.append(f"not ok {i} - {cell_id}")
            v = verdict or "no-verdict"
            lines.append(f"    # verdict: {v}")

    lines.append(f"1..{len(cells)}")
    return "\n".join(lines) + "\n"
