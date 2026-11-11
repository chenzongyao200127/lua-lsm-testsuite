"""Schema definitions for harness JSON: result.json (per cell), matrix.json
(aggregate), and the per-bundle metadata document.

Top-level documents carry a `schema_version` field for forward compatibility.
schema_version=2 is reserved for future additive changes; breaking changes to
existing field meanings would require a major bump and a migration note.

The Python types here are intentionally plain dicts so they round-trip through
json.dumps without custom encoders.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SCHEMA_VERSION = 1

# Verdicts the harness may produce. SKIP-class verdicts begin with the literal
# prefix "skip:" so downstream tooling (TAP emitter, matrix aggregator) can
# recognise them by prefix without an enumeration check.
VERDICTS = (
    "pass",
    "kernel-bug",
    "no-dmesg",
    "boot-timeout",
    "aborted",
    "workload-fail",
    "skip:stats-unavailable",
    "skip:no-kvm",
    "skip:no-lkdtm",
    "skip:image-not-warm",
    "skip:fixture-missing",
    "build-fail",
    "harness-error",
)

# Verdicts treated as TAP-level FAIL. workload-fail covers the case where a
# guest-side workload (smoke registration, verify_module_cleanup, bench,
# unixbench, etc.) returned a non-zero exit code but the kernel produced no
# splat: the cell did not pass even though the kernel itself is healthy.
FAIL_VERDICTS = frozenset(
    {
        "kernel-bug",
        "no-dmesg",
        "boot-timeout",
        "aborted",
        "workload-fail",
        "harness-error",
        "build-fail",
    }
)

# Verdicts treated as TAP-level SKIP. With "stats-unavailable" renamed to
# "skip:stats-unavailable", every skip verdict carries the "skip:" prefix.
SKIP_VERDICT_PREFIXES = ("skip:",)


def is_skip(verdict: str) -> bool:
    return verdict.startswith("skip:")


def is_fail(verdict: str) -> bool:
    return verdict in FAIL_VERDICTS


def is_pass(verdict: str) -> bool:
    return verdict == "pass"


# Normative verdict-to-classification table. TAP/KTAP and bisect-run modes MUST
# consult this mapping (or the is_pass/is_fail/is_skip helpers, which are kept
# in lock-step with it) so that a verdict is classified the same way wherever
# it appears.
VERDICT_CLASSIFICATION: dict[str, str] = {
    "pass": "pass",
    "kernel-bug": "fail",
    "no-dmesg": "fail",
    "boot-timeout": "fail",
    "aborted": "fail",
    "workload-fail": "fail",
    "harness-error": "fail",
    "build-fail": "fail",
    "skip:stats-unavailable": "skip",
    "skip:no-kvm": "skip",
    "skip:no-lkdtm": "skip",
    "skip:image-not-warm": "skip",
    "skip:fixture-missing": "skip",
}


# AC-5.1 counter keys. snapshots.{before,after}.counters MUST contain at least
# these keys; missing keys indicate a partial or malformed snapshot. All values
# are non-negative integers (Python int, JSON number).
REQUIRED_COUNTER_KEYS: tuple[str, ...] = (
    "lvm.nalloc",
    "lvm.nfree",
    "lvm.nusage",
    "lmem.nalloc",
    "lmem.nrealloc",
    "lmem.nfree",
    "lmem.total",
    "lmem.average",
    "lmem.minimum",
    "lmem.maximum",
    "kvcache.nalloc",
    "kvcache.nfree",
    "kvcache.nusage",
)


# AC-5.1 lsm_funcs row keys. Each row in perf.snapshots.{before,after}.lsm_funcs
# MUST carry these fields when serialised as a row. The on-disk shape used by
# this harness is dict-keyed-by-name (`lsm_funcs[name] = {nlsm,count,...}`),
# where the dict key supplies the AC-5.1 `name` column.
LSM_FUNCS_ROW_KEYS: tuple[str, ...] = ("name", "nlsm", "count", "total", "average", "maxtime")


def lsm_funcs_row(
    name: str, nlsm: int, count: int, total: int, average: int, maxtime: int
) -> dict[str, Any]:
    """Build an AC-5.1-shaped lsm_funcs row.

    Helpers consume the dict-keyed-by-name shape; this builder is provided for
    callers that need to emit an array-of-rows form (e.g. when forwarding to a
    consumer that expects the AC-5.1 literal shape).
    """
    return {
        "name": name,
        "nlsm": nlsm,
        "count": count,
        "total": total,
        "average": average,
        "maxtime": maxtime,
    }


def empty_result(cell_id: str) -> dict[str, Any]:
    """Build a minimal-shape result.json populated with placeholders.

    Callers fill in fields as the cell progresses. The schema_version field is
    set here once and not touched by the runner.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "cell_id": cell_id,
        "started_at": None,
        "finished_at": None,
        "qemu_pid": None,
        "kernel_image": None,
        "rootfs_image": None,
        "kconfig_profile": None,
        "cmdline": None,
        "workload": None,
        "verdict": None,
        "reason": None,
        "classifier_hits": [],
        "classifier_pattern_version": None,
        "journalctl_hits": [],
        "perf": {"snapshots": None, "deltas": None},
        "artifacts": {
            "serial_log": "serial.log",
            "dmesg_log": "dmesg.log",
            "journalctl_log": "journalctl-kb.txt",
        },
        "host": {
            "system": None,
            "release": None,
            "has_kvm": None,
        },
    }


def empty_matrix() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "started_at": None,
        "finished_at": None,
        "host": {"system": None, "release": None, "has_kvm": None},
        "config": {"parallel": None, "matrix_path": None},
        "totals": {
            "planned": 0,
            "executed": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "aborted": 0,
        },
        "cells": [],
    }


def aggregate_totals(cells: list[Mapping[str, Any]]) -> dict[str, int]:
    totals = {
        "planned": len(cells),
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "aborted": 0,
    }
    for c in cells:
        verdict = c.get("verdict")
        if verdict is None:
            continue
        totals["executed"] += 1
        if is_pass(verdict):
            totals["passed"] += 1
        elif verdict == "aborted":
            totals["aborted"] += 1
        elif is_fail(verdict):
            totals["failed"] += 1
        elif is_skip(verdict):
            totals["skipped"] += 1
    return totals


def aggregate_verdict(totals: Mapping[str, int]) -> str:
    """Matrix-level verdict for bisect-run / KSFT exit-code aggregation.

    Returns one of: "pass", "fail", "skip-all", "no-cells".
    A single failed cell makes the matrix fail. If no cells failed but every
    executed cell skipped, the matrix is "skip-all". Otherwise "pass".
    """
    executed = int(totals.get("executed", 0))
    failed = int(totals.get("failed", 0)) + int(totals.get("aborted", 0))
    passed = int(totals.get("passed", 0))
    skipped = int(totals.get("skipped", 0))
    if executed == 0:
        return "no-cells"
    if failed > 0:
        return "fail"
    if passed == 0 and skipped == executed:
        return "skip-all"
    return "pass"


# Per-bundle reproducer payload. The bundle is the bisect-ready snapshot a
# kernel developer needs to reproduce a splat: kernel sha and config so the
# build is reproducible, cmdline + commands.sh + policies/ so the cell is
# replayable, rootfs sha for image identity, raw serial/dmesg slice for the
# original signal, decoded.txt for human-readable trace, and signature so
# dedup is deterministic. metadata.json is written alongside as harness
# bookkeeping (signature kind, cell id, dup_of pointer) and is not part of
# the user-facing payload count.
BUNDLE_FILES: tuple[str, ...] = (
    "kernel.sha",
    ".config",
    "config.diff",
    "cmdline",
    "commands.sh",
    "policies",
    "rootfs.sha256",
    "serial.log",
    "dmesg.txt",
    "decoded.txt",
    "signature",
)

SIGNATURE_KINDS: tuple[str, ...] = ("primary", "fallback")


# kconfig profiles passed to the vendored enable-debug-kconfig.sh. The harness
# refuses anything outside this set at planning time so a typo can't slip past
# the cell builder and consume QEMU launch time.
VALID_KCONFIG_PROFILES: frozenset[str] = frozenset({"standard", "full"})


class KconfigProfileError(ValueError):
    """Raised when a cell or run requests an unknown kconfig profile."""


def assert_kconfig_profile(profile: str | None) -> None:
    """Refuse profiles that aren't in VALID_KCONFIG_PROFILES.

    None is accepted (callers may not set the profile when --build-kernel is
    not requested). Any other value is rejected with a list of valid choices
    so the user sees what was wrong without consulting the source.
    """
    if profile is None:
        return
    if profile not in VALID_KCONFIG_PROFILES:
        valid = ", ".join(sorted(VALID_KCONFIG_PROFILES))
        raise KconfigProfileError(f"unknown kconfig profile {profile!r}; valid choices: {valid}")


def empty_bundle_metadata(cell_id: str, signature_sha1: str, signature_kind: str) -> dict[str, Any]:
    """Build the bundle/metadata.json shape.

    Callers populate first_seen_at / dup_of as needed. `signature_kind` MUST be
    one of SIGNATURE_KINDS; raise ValueError on misuse rather than silently
    accepting a typo (this metadata drives dedup, so a typo would split a real
    duplicate cluster).
    """
    if signature_kind not in SIGNATURE_KINDS:
        raise ValueError(f"signature_kind must be one of {SIGNATURE_KINDS}, got {signature_kind!r}")
    return {
        "schema_version": SCHEMA_VERSION,
        "cell_id": cell_id,
        "signature_sha1": signature_sha1,
        "signature_kind": signature_kind,
        "first_seen_at": None,
        "dup_of": None,
        "files": list(BUNDLE_FILES),
    }
