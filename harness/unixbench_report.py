"""UnixBench score extraction and report-only aggregation.

The perf cells are deliberately not pass/fail: shared CI runners cannot give
a trustworthy noise budget, so this module only turns `unixbench.log` into
structured scores plus a Markdown/JSON report. A future gate can consume the
same structure once a baseline methodology exists.

UnixBench 5.1.3 prints one summary score plus a table of per-test index
values::

    System Benchmarks Index Values               BASELINE       RESULT    INDEX
    Dhrystone 2 using register variables         116700.0   21587377.2   1849.8
    ...
    System Benchmarks Index Score                                         1588.1

The parser is intentionally tolerant: missing summary or table yields
`None`/empty instead of raising, so a crashed wrapper still produces a
report row showing the cell verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_INDEX_SCORE_RE = re.compile(
    r"^System Benchmarks Index Score\s+([0-9]+(?:\.[0-9]+)?)\s*$", re.MULTILINE
)
_INDEX_ROW_RE = re.compile(
    r"^(?P<name>\S.*?)\s{2,}(?P<baseline>[0-9]+(?:\.[0-9]+)?)\s+"
    r"(?P<result>[0-9]+(?:\.[0-9]+)?)\s+(?P<index>[0-9]+(?:\.[0-9]+)?)\s*$"
)
_CPU_RE = re.compile(
    r"^(?P<cpus>\d+)\s+CPUs?\s+in\s+system;\s+running\s+(?P<parallel>\d+)\s+parallel\s+cop(?:y|ies)",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class UnixBenchScore:
    index_score: float | None = None
    tests: dict[str, float] = field(default_factory=dict)
    cpus: int | None = None
    parallel: int | None = None


def parse_log(text: str) -> UnixBenchScore:
    """Extract the summary score, per-test indices, and CPU counts."""
    score_matches = _INDEX_SCORE_RE.findall(text)
    index_score = float(score_matches[-1]) if score_matches else None

    tests: dict[str, float] = {}
    lines = text.splitlines()
    in_table = False
    for line in lines:
        if "System Benchmarks Index Values" in line:
            in_table = True
            continue
        if in_table and ("Index Values" in line or "Index Score" in line):
            # Reached the next category or the summary line.
            in_table = False
            continue
        if not in_table:
            continue
        if not line.strip():
            continue
        match = _INDEX_ROW_RE.match(line)
        if match:
            tests[match.group("name").strip()] = float(match.group("index"))

    cpus = parallel = None
    cpu_match = _CPU_RE.search(text)
    if cpu_match:
        cpus = int(cpu_match.group("cpus"))
        parallel = int(cpu_match.group("parallel"))

    return UnixBenchScore(
        index_score=index_score, tests=tests, cpus=cpus, parallel=parallel
    )


@dataclass(frozen=True)
class CellScore:
    cell_id: str
    policy: str
    lsm: str
    nodebug: bool
    verdict: str | None
    artifact_dir: Path
    score: UnixBenchScore


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def collect(runs_root: Path) -> list[CellScore]:
    """Walk a runs/ tree and return one entry per UnixBench cell with a log."""
    out: list[CellScore] = []
    for result_path in sorted(Path(runs_root).rglob("result.json")):
        cell_dir = result_path.parent
        log_path = cell_dir / "unixbench.log"
        if not log_path.exists():
            continue
        result = _load_json(result_path)
        if result.get("workload") not in (None, "unixbench"):
            continue
        cell = _load_json(cell_dir / "cell.json")
        profile = cell.get("profile") or {}
        out.append(
            CellScore(
                cell_id=str(result.get("cell_id") or cell_dir.name),
                policy=str(profile.get("policy", "unknown")),
                lsm=str(profile.get("lsm", "")),
                nodebug=bool(profile.get("nodebug", False)),
                verdict=result.get("verdict"),
                artifact_dir=cell_dir,
                score=parse_log(log_path.read_text(errors="replace")),
            )
        )
    return out


def _policy_label(policy: str) -> str:
    if "/" in policy:
        return Path(policy).stem
    return policy


def medians(cells: list[CellScore]) -> dict[str, float]:
    """Median summary score per policy label, ignoring unscored cells."""
    grouped: dict[str, list[float]] = {}
    for cell in cells:
        if cell.score.index_score is None:
            continue
        grouped.setdefault(_policy_label(cell.policy), []).append(cell.score.index_score)
    out: dict[str, float] = {}
    for label, values in grouped.items():
        values.sort()
        mid = len(values) // 2
        if len(values) % 2:
            out[label] = values[mid]
        else:
            out[label] = (values[mid - 1] + values[mid]) / 2.0
    return out


def render_markdown(cells: list[CellScore]) -> str:
    """Render a human-readable report; never raises on missing scores."""
    lines = ["## UnixBench report", ""]
    if not cells:
        lines.append("_No UnixBench cells found._")
        return "\n".join(lines) + "\n"

    lines.append("| cell | policy | lsm | nodebug | verdict | index score |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for cell in cells:
        score = cell.score.index_score
        score_text = "n/a" if score is None else f"{score:.1f}"
        lines.append(
            f"| {cell.cell_id} | {_policy_label(cell.policy)} | "
            f"{cell.lsm or '-'} | {cell.nodebug} | {cell.verdict or '-'} | {score_text} |"
        )

    summary = medians(cells)
    if summary:
        lines.extend(["", "### Median index score", "", "| policy | median |", "| --- | --- |"])
        for label in sorted(summary):
            lines.append(f"| {label} | {summary[label]:.1f} |")

    lines.extend(
        [
            "",
            "_Report-only: perf cells do not fail CI. Compare medians across "
            "repetitions on the same runner before drawing conclusions._",
        ]
    )
    return "\n".join(lines) + "\n"


def as_dict(cells: list[CellScore]) -> dict[str, Any]:
    return {
        "cells": [
            {
                "cell_id": cell.cell_id,
                "policy": cell.policy,
                "lsm": cell.lsm,
                "nodebug": cell.nodebug,
                "verdict": cell.verdict,
                "artifact_dir": str(cell.artifact_dir),
                "index_score": cell.score.index_score,
                "tests": cell.score.tests,
                "cpus": cell.score.cpus,
                "parallel": cell.score.parallel,
            }
            for cell in cells
        ],
        "medians": medians(cells),
    }
