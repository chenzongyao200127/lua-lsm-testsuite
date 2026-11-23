"""Compose the guest kernel cmdline (EXTRA_CMDLINE) from a per-cell profile.

Profile shape (Python dict):

    {
        "kind": "perf" | "bughunt" | "bench", # required
        "lsm": "capability,yama,lua,...",     # optional; appended verbatim if present
        "lvm_pool_max": int | None,           # optional; only emitted if not None
        "nodebug": bool,                      # optional; default False
        "extra": [str, ...],                  # optional; appended verbatim
        "panic_on_warn": bool,                # optional; bughunt only, default True
    }

The composer is deliberately strict: a perf cell that already carries any of
the bug-hunt knobs is rejected so that timing comparisons are not silently
distorted by panic_on_warn / oops=panic.

A bughunt cell may set panic_on_warn=False to drop the panic knobs; the
matrix is then expected to baseline known base-kernel splat noise through
`known_splats` (consumed by cell_runner) instead of relying on an in-guest
panic to stop the run.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping

BUGHUNT_KNOBS = ("panic_on_warn=1", "panic=-1", "oops=panic")
VALID_KINDS = ("perf", "bughunt", "bench")


class CmdlineError(ValueError):
    """Raised when a profile cannot be turned into a valid cmdline."""


def compose(profile: Mapping) -> str:
    """Return the EXTRA_CMDLINE string for the given profile.

    The result is a single space-separated string suitable for assignment to
    the EXTRA_CMDLINE environment variable consumed by the local
    run_qemu_anolis.sh launcher.
    """
    kind = profile.get("kind")
    if kind not in VALID_KINDS:
        raise CmdlineError(f"profile.kind must be one of {VALID_KINDS}, got {kind!r}")

    extra: Iterable[str] = profile.get("extra") or ()
    extra_list = list(extra)

    if kind in ("perf", "bench"):
        for knob in BUGHUNT_KNOBS:
            if any(knob in tok for tok in extra_list):
                raise CmdlineError(
                    f"{kind} cell carries bug-hunt knob {knob!r}; refuse to start "
                    "(perf timing must not be distorted by panic_on_warn/oops=panic)"
                )

    parts: list[str] = []

    lsm = profile.get("lsm")
    if lsm:
        parts.append(f"lsm={lsm}")

    pool_max = profile.get("lvm_pool_max")
    if pool_max is not None:
        if not isinstance(pool_max, int) or pool_max < 0:
            raise CmdlineError(f"lvm_pool_max must be a non-negative int, got {pool_max!r}")
        parts.append(f"lua.lvm_pool_max={pool_max}")

    if profile.get("nodebug"):
        parts.append("lua.nodebug")

    if kind == "bughunt" and profile.get("panic_on_warn", True):
        parts.extend(BUGHUNT_KNOBS)

    parts.extend(extra_list)

    return " ".join(parts)


def compose_env(
    profile: Mapping, base_env: Mapping[str, str] | None = None
) -> MutableMapping[str, str]:
    """Build an environment dict suitable for spawning the local launcher.

    Returns a fresh dict so the caller can layer additional knobs (HOST_SSH_PORT,
    SHARE_DIR, QEMU_EXTRA_ARGS, ...) on top.
    """
    env: dict[str, str] = dict(base_env or {})
    env["EXTRA_CMDLINE"] = compose(profile)
    return env
