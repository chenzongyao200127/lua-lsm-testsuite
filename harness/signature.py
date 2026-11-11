"""Build a stable signature for a kernel splat suitable for bundle dedup.

The primary signature is sha1 of:
    top-frame-symbol+offset
    + "\n"
    + next 5 frame symbols stripped of addresses

If no decodable stack frames are present, a fallback signature is computed
from the first matched pattern + the surrounding 5-line slice, and recorded
with signature_kind == "fallback".

Address tokens like "ffffffff81234567" or "+0x1c/0x40" are stripped from
the frame symbols (but the leading symbol of the top frame keeps its offset
so identical-symbol-different-offset stacks dedup separately as documented).
"""

from __future__ import annotations

import hashlib
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

# Lines that look like a stack frame (decoded or otherwise).
# Examples this should match:
#   " [<ffffffff812345>] lua_hook_dispatch+0x80/0x140"
#   " ? lua_hook_dispatch+0x80/0x140 [security_lua]"
#   "lua_hook_dispatch+0x80/0x140"
_FRAME_RE = re.compile(
    r"""
    (?:\s*\?\s*)?                     # optional "? " prefix from decoded traces
    (?P<symbol>[A-Za-z_][\w.\$]*)     # symbol name
    (?P<offset>\+0x[0-9a-fA-F]+)?     # +0x1c
    (?P<size>/0x[0-9a-fA-F]+)?        # /0x40
    (?:\s*\[[^\]]+\])?                # optional [module]
    \s*$
    """,
    re.VERBOSE,
)

# Tokens that look like raw addresses, stripped before hashing for stability.
_ADDR_RE = re.compile(r"\b[0-9a-f]{8,16}\b|\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+")

# Frames we ignore at the top of the trace (architectural noise + KASAN/UBSAN
# reporting machinery). The signature should be stable regardless of whether
# the splat is reported via warn / KASAN / UBSAN; the meaningful top frame is
# the offending kernel callsite below the reporter.
_SKIP_SYMBOLS = (
    "dump_stack",
    "dump_stack_lvl",
    "show_stack",
    "show_trace",
    "__warn",
    "warn_slowpath_common",
    "warn_slowpath_fmt",
    "report_bug",
    "handle_bug",
    "exc_invalid_op",
    "asm_exc_invalid_op",
    "do_trap",
    # KASAN reporter machinery
    "kasan_report",
    "__kasan_report",
    "print_address_description",
    "print_report",
    "kasan_save_track",
    "kasan_save_alloc_info",
    "kasan_save_free_info",
    "__asan_report",
    "__hwasan_report",
    # UBSAN reporter machinery
    "ubsan_epilogue",
    "ubsan_prologue",
    "__ubsan_handle",
    # KCSAN reporter machinery
    "kcsan_report",
)


@dataclass(frozen=True)
class Signature:
    sha1: str
    kind: str  # "primary" or "fallback"
    top_frame: str | None
    frames: tuple[str, ...]


def _extract_frames(lines: Iterable[str]) -> list[str]:
    """Return symbol names (with optional offset for the top frame) from a slice.

    Only frames whose symbols look like real kernel symbols are returned;
    architectural skip-symbols are filtered out at signature-build time.
    """
    frames: list[str] = []
    for raw in lines:
        text = raw.strip().lstrip("[?] ").rstrip()
        if not text:
            continue
        m = _FRAME_RE.match(text)
        if not m:
            continue
        symbol = m.group("symbol")
        if symbol.startswith("0x") or symbol.isdigit():
            continue
        frames.append(text)
    return frames


def build_signature(
    decoded_or_raw: Sequence[str],
    pattern_label: str | None = None,
    surrounding_slice: Sequence[str] | None = None,
) -> Signature:
    """Build a stable signature from a list of log/decoded lines.

    decoded_or_raw should contain the lines that follow a Call Trace: anchor
    (or a kernel BUG/Oops header line). If no usable frames are extracted,
    the function falls back to hashing the pattern label plus the
    surrounding_slice (or decoded_or_raw if None).
    """
    frames = _extract_frames(decoded_or_raw)
    real_frames = [f for f in frames if not any(skip in f for skip in _SKIP_SYMBOLS)]

    if real_frames:
        top = real_frames[0]
        rest = real_frames[1:6]
        # The top frame keeps its offset; the rest are stripped of addresses.
        rest_clean = [_ADDR_RE.sub("", f).strip() for f in rest]
        payload = top + "\n" + "\n".join(rest_clean)
        digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()
        return Signature(sha1=digest, kind="primary", top_frame=top, frames=(top, *rest_clean))

    # Fallback: no decodable frames.
    slice_text = "\n".join(surrounding_slice if surrounding_slice is not None else decoded_or_raw)
    payload = (pattern_label or "<no-pattern>") + "\n" + slice_text
    short_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:64]
    digest = hashlib.sha1(
        (pattern_label or "<no-pattern>" + ":" + short_hash).encode("utf-8")
    ).hexdigest()
    return Signature(sha1=digest, kind="fallback", top_frame=None, frames=())


def selftest() -> int:
    failures: list[str] = []

    decoded_a = [
        "BUG: KASAN: use-after-free in lua_hook_dispatch+0x80/0x140 [security_lua]",
        "Read of size 8 at addr ffff88800a1b2c00 by task bench/123",
        "",
        "Call Trace:",
        " <TASK>",
        " dump_stack_lvl+0x33/0x50",
        " print_address_description+0x33/0x350",
        " print_report+0xc/0x1f0",
        " kasan_report+0xb1/0xe0",
        " lua_hook_dispatch+0x80/0x140 [security_lua]",
        " security_file_open+0x60/0xb0",
        " do_dentry_open+0x180/0x4c0",
        " path_openat+0x9d0/0xe40",
        " do_filp_open+0xe1/0x1d0",
    ]
    decoded_b = [
        # Same fault path, different reporter framing — must dedup with A.
        "BUG: KASAN: use-after-free in lua_hook_dispatch+0x80/0x140 [security_lua]",
        "Call Trace:",
        " dump_stack_lvl+0x33/0x50",
        " kasan_report+0xb1/0xe0",
        " lua_hook_dispatch+0x80/0x140 [security_lua]",
        " security_file_open+0x60/0xb0",
        " do_dentry_open+0x180/0x4c0",
        " path_openat+0x9d0/0xe40",
        " do_filp_open+0xe1/0x1d0",
    ]
    decoded_c = [
        # Different top frame -- must NOT dedup with A/B.
        "BUG: KASAN: use-after-free in luaH_set+0x10/0x80 [security_lua]",
        "Call Trace:",
        " dump_stack_lvl+0x33/0x50",
        " kasan_report+0xb1/0xe0",
        " luaH_set+0x10/0x80 [security_lua]",
        " lua_table_assign+0x40/0x90 [security_lua]",
    ]

    sig_a = build_signature(decoded_a)
    sig_b = build_signature(decoded_b)
    sig_c = build_signature(decoded_c)

    if sig_a.kind != "primary":
        failures.append(f"sig_a kind={sig_a.kind} expected=primary")
    if sig_a.sha1 != sig_b.sha1:
        failures.append(
            f"sig_a/sig_b should match (same top frame and 5 surrounding frames):\n"
            f"  a={sig_a.sha1} top={sig_a.top_frame!r}\n"
            f"  b={sig_b.sha1} top={sig_b.top_frame!r}"
        )
    if sig_a.sha1 == sig_c.sha1:
        failures.append(
            "sig_a/sig_c must differ (different top frames):\n"
            f"  a={sig_a.sha1} top={sig_a.top_frame!r}\n"
            f"  c={sig_c.sha1} top={sig_c.top_frame!r}"
        )

    fallback = build_signature(
        ["random text with no Call Trace frames"],
        pattern_label="watchdog: BUG: soft lockup",
        surrounding_slice=[
            "watchdog: BUG: soft lockup - CPU#0 stuck for 22s!",
            "Hardware name: ...",
        ],
    )
    if fallback.kind != "fallback":
        failures.append(f"fallback kind={fallback.kind} expected=fallback")
    if len(fallback.sha1) != 40:
        failures.append(f"fallback sha1 length={len(fallback.sha1)} expected=40")

    if failures:
        print("signature selftest FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("signature selftest OK (primary stable; fallback distinct)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    print("usage: python -m harness.signature --selftest")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
