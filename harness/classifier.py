"""Classify a captured kernel log against the anchored splat-header pattern set.

A "hit" is recorded as {pattern, line, substring} where:
- pattern is the human-readable label from classifier_patterns
- line is 1-based line number in the input
- substring is the matched span text
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from .classifier_patterns import PATTERN_VERSION, PATTERNS


@dataclass(frozen=True)
class ClassifierHit:
    pattern: str
    line: int
    substring: str

    def to_dict(self) -> dict:
        return asdict(self)


def classify_lines(lines: Iterable[str]) -> list[ClassifierHit]:
    hits: list[ClassifierHit] = []
    for lineno, raw in enumerate(lines, start=1):
        text = raw.rstrip("\n")
        for cp in PATTERNS:
            m = cp.regex.search(text)
            if m:
                hits.append(ClassifierHit(pattern=cp.label, line=lineno, substring=m.group(0)))
                break  # one hit per line is enough
    return hits


def classify_text(text: str) -> list[ClassifierHit]:
    return classify_lines(text.splitlines())


def classify_files(paths: Iterable[Path]) -> list[ClassifierHit]:
    """Classify the concatenation of multiple log files.

    The harness uses two channels (serial + in-guest dmesg). Either is
    sufficient for classification; if both are missing or empty, the caller
    is responsible for emitting verdict == "no-dmesg".
    """
    aggregate: list[ClassifierHit] = []
    line_offset = 0
    for path in paths:
        if not path or not Path(path).exists():
            continue
        text = Path(path).read_text(errors="replace")
        if not text.strip():
            continue
        for hit in classify_text(text):
            aggregate.append(
                ClassifierHit(
                    pattern=hit.pattern,
                    line=hit.line + line_offset,
                    substring=hit.substring,
                )
            )
        line_offset += text.count("\n") + 1
    return aggregate


def classify_files_per_channel(paths: Iterable[Path]) -> dict[Path, list[ClassifierHit]]:
    """Classify each log file independently with per-file local line numbers.

    Unlike classify_files (which renumbers hits with cross-file offsets to
    produce one aggregate line space), this returns a {path: hits} map where
    each hit's `line` field is the 1-based line number within that file
    alone. Callers that need to slice the channel containing the first hit
    rely on this shape so they can index back into the file's own line list.
    """
    out: dict[Path, list[ClassifierHit]] = {}
    for path in paths:
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            continue
        text = p.read_text(errors="replace")
        if not text.strip():
            out[p] = []
            continue
        out[p] = classify_text(text)
    return out


def has_any_log(paths: Iterable[Path]) -> bool:
    """Return True if at least one of the dmesg paths exists with content."""
    for path in paths:
        if path and Path(path).exists() and Path(path).read_text(errors="replace").strip():
            return True
    return False


def verdict_for_hits(hits: list[ClassifierHit]) -> str:
    return "kernel-bug" if hits else "pass"


def pattern_version() -> int:
    return PATTERN_VERSION


def iter_hit_dicts(hits: Iterable[ClassifierHit]) -> Iterator[dict]:
    return (h.to_dict() for h in hits)
