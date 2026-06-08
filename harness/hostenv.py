"""Host-environment detection: refuse macOS at planning time, SKIP missing KVM.

The harness deliberately refuses to run on Darwin (macOS): TCG-on-macOS perf
numbers would be misleading, and the kernel-VM workflow this harness drives
needs a Linux build host. On Linux without /dev/kvm, we still let the matrix
plan and skip per-cell with a remediation hint.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass


# Env var that operator scripts and the no-KVM acceptance test use to force
# `has_kvm=False` from a host that happens to have /dev/kvm. Honored only when
# the caller does NOT pass an explicit kvm_path= override, so production
# callers stay deterministic and the env var cannot leak into normal runs by
# accident. Pointing this at any non-existent path makes hostenv detection
# report no KVM while leaving kvm_required=True, which is exactly the input
# the cell_runner skip:no-kvm branch needs.
KVM_PATH_ENV = "LUA_LSM_TESTSUITE_KVM_PATH"


@dataclass(frozen=True)
class HostEnv:
    system: str
    release: str
    has_kvm: bool


def detect(system_override: str | None = None,
           kvm_path: str | None = None,
           release_override: str | None = None) -> HostEnv:
    """Inspect the host. Test code may override system/kvm_path for unit tests.

    The kvm_path lookup order is:
      1. The explicit kvm_path= argument when given (highest priority; lets
         unit tests pin a path without depending on process env state).
      2. The LUA_LSM_TESTSUITE_KVM_PATH env var when set (lets operator
         scripts force the no-KVM code path on hosts that have /dev/kvm).
      3. The hard default "/dev/kvm".
    """
    system = system_override if system_override is not None else platform.system()
    release = release_override if release_override is not None else platform.release()
    if kvm_path is None:
        kvm_path = os.environ.get(KVM_PATH_ENV, "/dev/kvm")
    has_kvm = os.path.exists(kvm_path)
    return HostEnv(system=system, release=release, has_kvm=has_kvm)


class UnsupportedHostError(SystemExit):
    """Raised on Darwin (macOS) and any other host we refuse to run on.

    Subclasses SystemExit so that, when raised from main(), the process exits
    with the carried code (default 2) without a Python traceback.
    """

    def __init__(self, message: str, code: int = 2):
        super().__init__(code)
        self.message = message


def assert_supported(host: HostEnv) -> None:
    """Refuse to start on Darwin. Other hosts pass through."""
    if host.system == "Darwin":
        raise UnsupportedHostError(
            "error: this harness requires a Linux host with /dev/kvm; "
            "macOS is not supported. Use a Linux build host or a Linux VM."
        )


def kvm_skip_payload(remediation: str | None = None) -> dict[str, object]:
    """Return the SKIP-class payload for a cell that cannot use /dev/kvm."""
    if remediation is None:
        remediation = (
            "set QEMU_ACCEL=tcg CPU_MODEL=max in the cell environment to run "
            "via TCG; perf numbers will not be comparable to KVM runs."
        )
    return {
        "verdict": "skip:no-kvm",
        "reason": "/dev/kvm is unavailable on this host",
        "remediation": remediation,
    }


def cell_kvm_check(host: HostEnv, kvm_required: bool) -> dict[str, object] | None:
    """If a cell requires KVM and the host lacks it, return the SKIP payload.

    Returns None when no skip is needed (host has KVM, or cell does not require it).
    """
    if kvm_required and not host.has_kvm:
        return kvm_skip_payload()
    return None
