"""Classify a captured kernel log against the anchored splat-header pattern set.

A "hit" is recorded as {pattern, line, substring, text} where:
- pattern is the human-readable label from classifier_patterns
- line is 1-based line number in the input
- substring is the matched span text
- text is the full log line; `known_splats` baselines match against it, so a
  headline that starts with a stable splat header can be ignored by matrix
  config without widening the anchored pattern set
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from .classifier_patterns import PATTERNS


@dataclass(frozen=True)
class ClassifierHit:
    pattern: str
    line: int
    substring: str
    text: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def split_ignored(
    hits: Sequence[ClassifierHit], known_splats: Iterable[str]
) -> tuple[list[ClassifierHit], list[ClassifierHit]]:
    """Partition hits into (fatal, ignored) by `known_splats` regex matches.

    `known_splats` comes from matrix config and is meant for splat headers
    that are known base-kernel noise (e.g. a KCSAN report in mm code that
    fires on every boot of the debug kernel). A hit is ignored only when one
    of the patterns matches its full log line; everything else stays fatal
    so real regressions are still caught.
    """
    patterns = [re.compile(p) for p in known_splats]
    if not patterns:
        return list(hits), []
    fatal: list[ClassifierHit] = []
    ignored: list[ClassifierHit] = []
    for hit in hits:
        if any(p.search(hit.text) for p in patterns):
            ignored.append(hit)
        else:
            fatal.append(hit)
    return fatal, ignored


def classify_lines(lines: Iterable[str]) -> list[ClassifierHit]:
    hits: list[ClassifierHit] = []
    for lineno, raw in enumerate(lines, start=1):
        text = raw.rstrip("\n")
        for cp in PATTERNS:
            m = cp.regex.search(text)
            if m:
                hits.append(
                    ClassifierHit(
                        pattern=cp.label,
                        line=lineno,
                        substring=m.group(0),
                        text=text,
                    )
                )
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
                    text=hit.text,
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
