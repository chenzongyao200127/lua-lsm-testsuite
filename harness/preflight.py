"""Preflight checks: enforce harness preconditions before launching cells.

Two categories of preflight:

- planner-level: image warmth, kernel image presence, rootfs presence. These
  decide which cells are even worth launching.
- guest-level: workload binaries, host_share mount, securityfs mount.
  Run after SSH comes up but before workload execution; emit
  skip:fixture-missing with a remediation note rather than letting the
  workload fail with a noisy secondary error.

Each helper returns either None (precondition met) or a SKIP payload dict
shaped like {"verdict": "skip:...", "reason": <str>, "remediation": <str>}.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from . import ssh


def default_warm_marker(image_path: Path) -> Path:
    """Return the conventional warm-marker path next to a rootfs image.

    Used both by the `image-warm` CLI subcommand (which writes the file) and
    by the perf-cell preflight gate (which reads it) so both sides agree on
    the lookup path without threading the explicit path through every cell.
    """
    p = Path(image_path)
    return p.with_suffix(p.suffix + ".warm-marker")


def image_warm_check(image_path: Path | None, warm_marker: Path | None) -> Mapping[str, str] | None:
    """SKIP if the rootfs image isn't marked warm.

    A rootfs is "warm" when it has a sentinel file (typically
    `.warm-marker` placed by `make image-warm`) — boot-up of a fresh image
    can take 90s+ which dwarfs the cell's actual runtime, so cells that
    measure perf require a pre-warmed image.
    """
    if image_path is None or warm_marker is None:
        return None
    if not Path(warm_marker).exists():
        return {
            "verdict": "skip:image-not-warm",
            "reason": f"rootfs warm marker missing: {warm_marker}",
            "remediation": (
                f"run `make image-warm IMAGE={image_path}` once on this host to "
                f"create the marker; subsequent cells reuse it."
            ),
        }
    return None


def host_share_check(
    target: ssh.SshTarget, mount_point: str = "/mnt/host"
) -> Mapping[str, str] | None:
    """SKIP if the 9p host_share isn't mounted in the guest.

    Workloads that read host_share/{lua-lsm-tools,unixbench} would otherwise
    fail with a confusing "no such file or directory" error after SSH-up.
    """
    r = ssh.run(target, f"mountpoint -q {mount_point}", timeout_s=10.0)
    if r.returncode != 0:
        return {
            "verdict": "skip:fixture-missing",
            "reason": f"host_share not mounted at {mount_point}",
            "remediation": (
                f"ensure `ENABLE_SHARE=1 SHARE_DIR=<workspace>` was set when "
                f"launching QEMU, and that the guest fstab mounts host_share "
                f"at {mount_point}."
            ),
        }
    return None


def workload_binary_check(target: ssh.SshTarget, paths: list[str]) -> Mapping[str, str] | None:
    """SKIP if any required workload binary is missing inside the guest."""
    for p in paths:
        r = ssh.run(target, f"test -x {p}", timeout_s=10.0)
        if r.returncode != 0:
            return {
                "verdict": "skip:fixture-missing",
                "reason": f"required binary missing or not executable: {p}",
                "remediation": (
                    f"ensure the host_share workspace contains a built copy of "
                    f"{p}; run the workload's build step on the host first."
                ),
            }
    return None


def securityfs_lua_check(target: ssh.SshTarget) -> Mapping[str, str] | None:
    """SKIP if /sys/kernel/security/lua/ isn't present.

    For a perf cell, this is `skip:stats-unavailable` (the perf measurement
    has no surface). For a correctness cell it is NOT a skip — a kernel
    that built lua-lsm but didn't expose securityfs is a kernel bug. Callers
    must use this only on perf cells.
    """
    r = ssh.run(target, "test -d /sys/kernel/security/lua", timeout_s=10.0)
    if r.returncode != 0:
        return {
            "verdict": "skip:stats-unavailable",
            "reason": "/sys/kernel/security/lua/ missing",
            "remediation": (
                "build the kernel with CONFIG_SECURITY_LUA=y and ensure "
                "securityfs is mounted (usually under /sys/kernel/security)."
            ),
        }
    return None
