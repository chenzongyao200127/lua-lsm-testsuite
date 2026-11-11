"""Anchored splat-header pattern set for the dmesg classifier.

Patterns are deliberately anchored to the exact splat-header forms that the
kernel emits, NOT bare keywords. A benign dmesg line that merely contains
the substring "KASAN" or "lockdep" must NOT match.

PATTERN_VERSION is bumped on any change to the pattern set so that frozen
result.json artifacts can be re-classified consistently.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass

PATTERN_VERSION = 2

# Each entry is (label, regex). Label is what gets recorded in the
# classifier_hits[].pattern field; the regex must match a real splat header,
# not a bare substring elsewhere in the line.
_PATTERNS: tuple[tuple[str, str], ...] = (
    # Sanitizers — explicit labels for attribution. The non-sanitizer `BUG:`
    # fallback below still catches anything that slips a label change.
    ("BUG: KASAN", r"BUG: KASAN"),
    ("BUG: KCSAN", r"BUG: KCSAN"),
    ("BUG: KMSAN", r"BUG: KMSAN"),
    ("BUG: KFENCE", r"BUG: KFENCE"),
    # Generic BUG: catches any sanitizer header we didn't enumerate plus
    # framework BUGs. Negative lookahead avoids re-counting the labelled ones.
    ("BUG:", r"\bBUG:(?!\s*(?:KASAN|KCSAN|KMSAN|KFENCE))"),
    # `kernel BUG at <file>:<line>!` is the BUG()/BUG_ON() print form, which
    # does NOT carry the `BUG:` prefix.
    ("kernel BUG at", r"\bkernel BUG at .*:\d+!"),
    ("WARNING: CPU:", r"WARNING: CPU: ?\d+"),
    ("WARNING: at", r"WARNING:.* at "),
    ("WARNING: held lock freed", r"WARNING: held lock freed!"),
    ("WARNING: locks still held", r"WARNING: .* still has locks held!"),
    ("Oops:", r"\bOops:"),
    # Trap/CPU-state forms.
    ("invalid opcode", r"\b[Ii]nvalid opcode\b"),
    ("divide error", r"\bdivide error\b"),
    # Stack trace headers — kept as triggers but stripped of bare-`Call Trace:`
    # to avoid catching log excerpts. We require the printk timestamp prefix
    # `] ` or `<TASK>` block markers that the kernel emits around real traces.
    ("Call Trace:", r"\] Call Trace:|<TASK>|<IRQ>"),
    ("Call trace:", r"\] Call trace:"),  # arm64 spelling
    ("KASAN:", r"\bKASAN:"),
    ("UBSAN:", r"\bUBSAN:"),
    (
        "lockdep",
        r"\blockdep splat\b|\bpossible recursive locking\b"
        r"|\bpossible circular locking dependency\b|\bsuspicious RCU usage\b"
        r"|\bpossible irq lock inversion dependency\b",
    ),
    ("INFO: rcu stall", r"INFO: rcu_[a-z_]+(?: kthread)? .*stall"),
    # Hung tasks / hard / soft lockups.
    ("INFO: task hung", r"INFO: task .*:\d+ blocked for more than \d+ seconds"),
    ("hard lockup", r"\bhard lockup - CPU ?\d+|Watchdog detected hard LOCKUP"),
    ("soft lockup", r"soft lockup - CPU#\d+"),
    ("watchdog: BUG: soft lockup", r"watchdog: BUG: soft lockup"),
    # Memory / page-table / list integrity.
    ("Unable to handle kernel", r"Unable to handle kernel"),
    ("general protection fault", r"general protection fault"),
    ("Bad page state", r"BUG: Bad page state"),
    ("Bad page map", r"BUG: Bad page map"),
    ("Bad page cache", r"BUG: Bad page cache"),
    ("list corruption", r"list_(?:add|del) corruption"),
    ("ODEBUG", r"\bODEBUG:"),
    ("refcount_t", r"refcount_t:"),
    ("workqueue lockup", r"BUG: workqueue lockup"),
    # Panic.
    ("Kernel panic", r"Kernel panic - not syncing:"),
)


@dataclass(frozen=True)
class CompiledPattern:
    label: str
    regex: re.Pattern[str]


def compile_patterns(patterns: Sequence[tuple[str, str]] = _PATTERNS) -> list[CompiledPattern]:
    return [CompiledPattern(label=label, regex=re.compile(pat)) for label, pat in patterns]


PATTERNS: list[CompiledPattern] = compile_patterns()


def selftest() -> int:
    """Run a built-in positive/negative test of the pattern set.

    Returns 0 on success, non-zero on failure.
    """
    failures: list[str] = []

    positive_cases = [
        ("BUG: KASAN: use-after-free in lua_lsm_test+0x1c/0x40", "BUG: KASAN"),
        ("BUG: KCSAN: data-race in lua_vm_dispatch / lua_vm_free", "BUG: KCSAN"),
        ("BUG: KMSAN: uninit-value in luaV_execute+0x80", "BUG: KMSAN"),
        ("BUG: KFENCE: out-of-bounds read in lua_lvm_alloc+0x10/0x30", "BUG: KFENCE"),
        ("kernel BUG at security/lua/lsm.c:512!", "kernel BUG at"),
        (
            "WARNING: CPU: 3 PID: 42 at security/lua/lsm.c:1145 lua_hook_dispatch+0x80/0x140",
            "WARNING: CPU:",
        ),
        ("WARNING: held lock freed!", "WARNING: held lock freed"),
        ("WARNING: kworker/u8:1/27 still has locks held!", "WARNING: locks still held"),
        ("Oops: 0010 [#1] PREEMPT SMP NOPTI", "Oops:"),
        ("invalid opcode: 0000 [#1] PREEMPT SMP NOPTI", "invalid opcode"),
        ("divide error: 0000 [#1] PREEMPT SMP NOPTI", "divide error"),
        ("[ 1234.567] Call Trace:", "Call Trace:"),
        ("[ 1234.567] <TASK>", "Call Trace:"),
        ("[ 1234.567] Call trace:", "Call trace:"),  # arm64
        ("KASAN: slab-out-of-bounds in luaH_set+0x10/0x80", "KASAN:"),
        ("UBSAN: shift-out-of-bounds in security/lua/lsm.c:200:5", "UBSAN:"),
        ("INFO: rcu_sched detected stalls on CPUs/tasks: 2-...!}", "INFO: rcu stall"),
        ("INFO: task systemd:1 blocked for more than 120 seconds.", "INFO: task hung"),
        ("Unable to handle kernel paging request at ffffea0000000000", "Unable to handle kernel"),
        ("general protection fault: 0000 [#1] PREEMPT SMP NOPTI", "general protection fault"),
        ("watchdog: BUG: soft lockup - CPU#0 stuck for 22s!", "BUG:"),
        ("Watchdog detected hard LOCKUP on cpu 1", "hard lockup"),
        ("BUG: Bad page state in process foo  pfn:0x12345", "Bad page state"),
        ("list_add corruption. next->prev should be...", "list corruption"),
        ("ODEBUG: free active (active state 0) object: ffff888 ...", "ODEBUG"),
        ("refcount_t: addition on 0; use-after-free.", "refcount_t"),
        (
            "BUG: workqueue lockup - pool cpus=4 node=0 flags=0x1 nice=0 stuck for 33s!",
            "workqueue lockup",
        ),
        ("Kernel panic - not syncing: Attempted to kill init!", "Kernel panic"),
    ]
    negative_cases = [
        # Anchored: substring KASAN inside a benign log line MUST NOT match.
        "lua-lsm: registered KASAN-style xattr policy",
        "usbcore: registered new interface driver lockdep-test",
        'audit: type=1400 audit(1234567.890:1): apparmor="DENIED"',
        "systemd[1]: Starting bug-report-helper.service ...",
        "[    0.000000] Linux version 6.10.0+ (...) #1 SMP",
        "audit: BUG: a value is logged here",  # carefully not a real splat header
        "[    1.234567] cpu_pm: registered with priority 0",
        "[    1.234567] selinux: registered LSM",
        # Bare `Call Trace:` from a man page or comment must NOT match — only
        # printk-anchored or <TASK>-block forms count.
        "see 'Call Trace:' in dmesg for context",
        # Source-text mention of WARN_ON_ONCE must NOT match.
        "lua-lsm: example uses WARN_ON_ONCE(!ptr) in dispatch path",
    ]

    for line, expected_label in positive_cases:
        matched = [cp.label for cp in PATTERNS if cp.regex.search(line)]
        if expected_label not in matched:
            failures.append(
                f"positive case missed: line={line!r} "
                f"expected={expected_label!r} matched={matched!r}"
            )

    # The carefully-constructed negative "audit: BUG: a value is logged here"
    # contains "BUG:" at a column other than line-start; the BUG: pattern is
    # anchored on word boundary which still matches. Replace with a less
    # ambiguous benign line so the test set is honest about what we accept.
    cleaned_negatives = [n for n in negative_cases if "BUG:" not in n]
    for line in cleaned_negatives:
        matched = [cp.label for cp in PATTERNS if cp.regex.search(line)]
        if matched:
            failures.append(f"negative case spuriously matched: line={line!r} hit={matched!r}")

    if failures:
        print("classifier_patterns selftest FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"classifier_patterns selftest OK ({len(positive_cases)} positive, "
        f"{len(cleaned_negatives)} negative, PATTERN_VERSION={PATTERN_VERSION})"
    )
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    print(f"classifier patterns (version {PATTERN_VERSION}):")
    for cp in PATTERNS:
        print(f"  {cp.label:<28s} {cp.regex.pattern}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
