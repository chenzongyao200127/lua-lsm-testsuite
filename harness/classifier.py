"""Classify a captured kernel log against the anchored splat-header pattern set.

A "hit" is recorded as {pattern, line, substring, text} where:
- pattern is the human-readable label from classifier_patterns
- line is 1-based line number in the input
- substring is the matched span text
- text is the full log line; `known_splats` baselines match against it, so a
  headline that starts with a stable splat header can be ignored by matrix
  config without widening the anchored pattern set
- block is the header plus the stack frames of the racing accesses; frames that
  only show what an interrupt landed on are excluded; `known_blocks` baselines
  match against it, which lets a rule reason over the whole report
  (e.g. ignore a sanitizer report only when no Lua symbol races)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from .classifier_patterns import PATTERNS

# End of a report block, e.g. "[ 16.44] ====..."; reports are framed by these.
_BLOCK_END = re.compile(r"^\s*(?:\[[^\]]*\]\s*)?=+\s*$")

# A stack-frame line, e.g. "[ 16.42]  luaV_execute+0x45b/0x5b0". Only these
# lines are kept: the surrounding "Comm: ... <version>" line embeds the kernel
# release string, which must not be mistaken for a Lua symbol.
_STACK_FRAME = re.compile(r"^\s*(?:\[[^\]]*\]\s*)?\s+[A-Za-z_][\w.]*\+0x[0-9a-f]+/0x[0-9a-f]+")

# An access-stack header inside a KCSAN report, e.g. "read to 0x... of 8 bytes
# by interrupt on cpu 0:". Each header starts a fresh stack, so the
# interrupted-context cut below applies per stack, not to the whole report.
_ACCESS_HEADER = re.compile(r"^\s*(?:\[[^\]]*\]\s*)?(?:read|write) to \S+ of \d+ bytes by ")

# An interrupt-entry frame, e.g. "asm_sysvec_apic_timer_interrupt+0x1a/0x20".
# Frames below such an entry belong to the task the interrupt landed on, not to
# the racing access: they are the bystander context a report happens to capture,
# not a participant. Entry symbols: asm_sysvec_*, sysvec_*, asm_exc_*, exc_*,
# asm_common_interrupt, error_entry.
_INTERRUPT_ENTRY = re.compile(
    r"(?:^|\s)(?:asm_)?(?:sysvec_|exc_|common_interrupt|error_entry)[\w.]*\+0x"
)

_MAX_BLOCK_LINES = 200


@dataclass(frozen=True)
class ClassifierHit:
    pattern: str
    line: int
    substring: str
    text: str = ""
    block: str = ""

    def to_dict(self) -> dict:
        # The block is deliberately not serialized: it is only used for
        # baseline matching and can be dozens of lines long.
        d = asdict(self)
        d.pop("block", None)
        return d


def _report_block(lines: Sequence[str], idx: int) -> str:
    """Header plus the racing stacks of the report starting at `lines[idx]`.

    A KCSAN report lists one stack per racing access, each introduced by a
    "read/write to ..." header. Frames below an interrupt-entry frame in a
    stack are the task the interrupt landed on: a bystander, not a racer.
    They are excluded so a rule can ask "is our code in the race?" without
    the answer depending on what the timer interrupt happened to interrupt.
    """
    block = [lines[idx]]
    interrupted = False
    for line in lines[idx + 1 : idx + 1 + _MAX_BLOCK_LINES]:
        if _BLOCK_END.match(line):
            break
        if _ACCESS_HEADER.match(line):
            interrupted = False
            continue
        if _STACK_FRAME.match(line):
            if _INTERRUPT_ENTRY.search(line):
                block.append(line)
                interrupted = True
            elif not interrupted:
                block.append(line)
    return "\n".join(block)


def split_ignored(
    hits: Sequence[ClassifierHit],
    known_splats: Iterable[str],
    known_blocks: Iterable[str] = (),
) -> tuple[list[ClassifierHit], list[ClassifierHit]]:
    """Partition hits into (fatal, ignored) by baseline regex matches.

    `known_splats` patterns are matched against the hit's log line and are
    meant for splat headers that are known base-kernel noise. `known_blocks`
    patterns are matched against the report block (header + stack frames),
    which suits rules that need the call stacks to decide. A hit is ignored
    only when one of the patterns matches; everything else stays fatal so
    real regressions are still caught.
    """
    line_patterns = [re.compile(p) for p in known_splats]
    block_patterns = [re.compile(p) for p in known_blocks]
    if not line_patterns and not block_patterns:
        return list(hits), []
    fatal: list[ClassifierHit] = []
    ignored: list[ClassifierHit] = []
    for hit in hits:
        if any(p.search(hit.text) for p in line_patterns) or any(
            p.search(hit.block) for p in block_patterns
        ):
            ignored.append(hit)
        else:
            fatal.append(hit)
    return fatal, ignored


def classify_lines(lines: Iterable[str]) -> list[ClassifierHit]:
    lines = [line.rstrip("\n") for line in lines]
    hits: list[ClassifierHit] = []
    for i, text in enumerate(lines):
        for cp in PATTERNS:
            m = cp.regex.search(text)
            if m:
                hits.append(
                    ClassifierHit(
                        pattern=cp.label,
                        line=i + 1,
                        substring=m.group(0),
                        text=text,
                        block=_report_block(lines, i),
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
                    block=hit.block,
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
