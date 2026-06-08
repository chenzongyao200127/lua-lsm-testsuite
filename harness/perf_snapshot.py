"""Parse /sys/kernel/security/lua/{stats,lsm_funcs} snapshots and compute deltas.

The kernel prints stats in tab-separated `key = value` form (lvm/lmem/kvcache
counters) and lsm_funcs as a fixed-width 7-column table. We parse both into
plain dicts so they can be diffed and round-tripped through JSON.

When either file is absent or empty, the caller should propagate
verdict == "skip:stats-unavailable" (a SKIP-class verdict), NOT a silent pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from . import schemas

# `key = value` lines from /sys/kernel/security/lua/stats and kvcache_stats_show.
_KV_RE = re.compile(r"^(?P<key>[A-Za-z][\w.]*)\s*=\s*(?P<value>-?\d+)\s*$")

# Header line from lsm_funcs that we recognise.
_FUNCS_HEADER_RE = re.compile(r"^\s*num\s+name\s+nlsm\s+count\s+total\s+average\s+maxtime\s*$")
_FUNCS_ROW_RE = re.compile(
    r"^\s*(?P<num>\d+)\s+(?P<name>\S+)\s+(?P<nlsm>\d+)\s+(?P<count>\d+)\s+"
    r"(?P<total>\d+)\s+(?P<average>\d+)\s+(?P<maxtime>\d+)\s*$"
)


@dataclass
class Snapshot:
    counters: dict[str, int] = field(default_factory=dict)
    lsm_funcs: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"counters": dict(self.counters), "lsm_funcs": {k: dict(v) for k, v in self.lsm_funcs.items()}}


def parse_stats_text(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for raw in text.splitlines():
        m = _KV_RE.match(raw)
        if not m:
            continue
        out[m.group("key")] = int(m.group("value"))
    return out


def parse_lsm_funcs_text(text: str) -> dict[str, dict[str, int]]:
    """Parse the lsm_funcs table into {name: {nlsm, count, total, average, maxtime}}.

    Lines preceding the recognised header (e.g. "stats for lua-lsm (ns)") and
    the divider lines are ignored.
    """
    out: dict[str, dict[str, int]] = {}
    in_table = False
    for raw in text.splitlines():
        if not in_table:
            if _FUNCS_HEADER_RE.match(raw):
                in_table = True
            continue
        m = _FUNCS_ROW_RE.match(raw)
        if not m:
            continue
        out[m.group("name")] = {
            "nlsm": int(m.group("nlsm")),
            "count": int(m.group("count")),
            "total": int(m.group("total")),
            "average": int(m.group("average")),
            "maxtime": int(m.group("maxtime")),
        }
    return out


def read_snapshot(stats_path: Path | None, lsm_funcs_path: Path | None) -> Snapshot | None:
    """Read both stats and lsm_funcs into a Snapshot, or return None if unavailable.

    Returns None when neither file exists. A partial snapshot (one file present,
    the other absent) is still returned with the missing side empty.
    """
    snap = Snapshot()
    any_present = False
    if stats_path and Path(stats_path).exists():
        any_present = True
        snap.counters = parse_stats_text(Path(stats_path).read_text(errors="replace"))
    if lsm_funcs_path and Path(lsm_funcs_path).exists():
        any_present = True
        snap.lsm_funcs = parse_lsm_funcs_text(Path(lsm_funcs_path).read_text(errors="replace"))
    if not any_present:
        return None
    return snap


def validate_snapshot(snap: Snapshot | None) -> str | None:
    """Validate a Snapshot against the required counter keys and a non-empty
    lsm_funcs table.

    Returns None when the snapshot is structurally complete: every required
    counter key in `schemas.REQUIRED_COUNTER_KEYS` is present AND at least one
    lsm_funcs row parsed. Returns a short reason string otherwise so the
    caller can finalize the cell as skip:stats-unavailable.

    A None snapshot is treated as missing entirely.
    """
    if snap is None:
        return "snapshot missing"
    missing = [k for k in schemas.REQUIRED_COUNTER_KEYS if k not in snap.counters]
    if missing:
        return "missing required counters: " + ",".join(missing)
    if not snap.lsm_funcs:
        return "lsm_funcs table empty (no rows parsed)"
    return None


def diff(before: Snapshot, after: Snapshot) -> dict:
    counters: dict[str, int] = {}
    for key in set(before.counters) | set(after.counters):
        counters[key] = after.counters.get(key, 0) - before.counters.get(key, 0)

    lsm_funcs: dict[str, dict[str, int]] = {}
    for hook in set(before.lsm_funcs) | set(after.lsm_funcs):
        b = before.lsm_funcs.get(hook, {})
        a = after.lsm_funcs.get(hook, {})
        lsm_funcs[hook] = {
            "nlsm": a.get("nlsm", b.get("nlsm", 0)),  # nlsm is a config not a counter
            "count": a.get("count", 0) - b.get("count", 0),
            "total": a.get("total", 0) - b.get("total", 0),
            "maxtime": a.get("maxtime", 0),  # max-of-max is post-snapshot maxtime
            "average_before": b.get("average", 0),
            "average_after": a.get("average", 0),
        }
    return {"counters": counters, "lsm_funcs": lsm_funcs}


def stats_available_skip_payload(reason: str = "CONFIG_SECURITY_LUA_LSM_STATS not enabled") -> Mapping[str, object]:
    """Helper that builds the SKIP-class payload for a perf cell with no stats."""
    return {
        "verdict": "skip:stats-unavailable",
        "reason": reason,
        "perf": {"snapshots": None, "deltas": None},
    }
