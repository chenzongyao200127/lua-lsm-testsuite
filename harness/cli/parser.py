"""Argument parser for `python3 -m harness`.

The four subcommands share a large block of identical arguments (kernel
images, SSH options, timeouts, kernel-build knobs), so those live in parent
parsers. The parents are constructed INSIDE build_parser() on every call:
several defaults (SSH_KEY, SSH_USER, SHARE_DIR, launcher, tools dir) are
environment-derived, and constructing them at call time keeps a test that
mutates os.environ from being served an import-time stale default.

Caution: argparse `parents=` shares action objects and default values
between subparsers. Every default here is immutable (Path/int/str/bool/
None), so sharing is safe; do not introduce a mutable default without
duplicating the parent.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .. import matrix, schemas, workloads
from .bisect_run import cmd_bisect_run
from .common import DEFAULT_LAUNCHER, DEFAULT_RUNS_ROOT, DEFAULT_TOOLS_DIR
from .image_warm import cmd_image_warm
from .matrix_cmd import cmd_matrix
from .run import cmd_run


def _cell_common_parent() -> argparse.ArgumentParser:
    """Arguments shared by `run`, `matrix`, and `bisect-run`."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--kernel", required=False, type=Path, help="bzImage path")
    p.add_argument("--rootfs", required=False, type=Path, help="rootfs image path")
    p.add_argument("--launcher", type=Path, default=DEFAULT_LAUNCHER)
    p.add_argument(
        "--ssh-key",
        type=Path,
        default=Path(os.environ.get("SSH_KEY", os.path.expanduser("~/.ssh/id_rsa"))),
    )
    p.add_argument("--ssh-user", default=os.environ.get("SSH_USER", "root"))
    p.add_argument(
        "--share-dir",
        type=Path,
        default=Path(os.environ["SHARE_DIR"]) if os.environ.get("SHARE_DIR") else None,
    )
    p.add_argument("--boot-timeout", type=float, default=180.0)
    p.add_argument("--workload-timeout", type=float, default=600.0)
    p.add_argument("--runs-root", type=Path, default=DEFAULT_RUNS_ROOT)
    p.add_argument(
        "--kconfig-profile",
        choices=sorted(schemas.VALID_KCONFIG_PROFILES),
        default=None,
        help="kconfig profile (standard|full)",
    )
    p.add_argument(
        "--build-kernel",
        action="store_true",
        help=(
            "invoke enable-debug-kconfig.sh --kernel <tree> "
            "--profile <X> before launch (requires --kernel-tree)"
        ),
    )
    p.add_argument(
        "--kernel-tree",
        type=Path,
        default=None,
        help="kernel source tree path (used for build + bundle)",
    )
    p.add_argument(
        "--debug-kernel",
        type=Path,
        default=DEFAULT_TOOLS_DIR,
        help="directory containing host build helpers",
    )
    p.add_argument(
        "--kernel-config",
        type=Path,
        default=None,
        help="kernel .config path to record in the bundle",
    )
    p.add_argument(
        "--kernel-config-baseline",
        type=Path,
        default=None,
        help="baseline .config to diff the active config against",
    )
    p.add_argument(
        "--decode-script",
        type=Path,
        default=None,
        help="path to scripts/decode_stacktrace.sh for bundle decode",
    )
    return p


def _parallel_common_parent() -> argparse.ArgumentParser:
    """Arguments shared by `matrix` and `bisect-run` (port range + parallelism)."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--port-base", type=int, default=matrix.DEFAULT_PORT_BASE)
    p.add_argument("--parallel", type=int, default=1)
    return p


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 -m harness",
        description="Out-of-tree QEMU matrix harness for the Linux Lua LSM",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    cell_common = _cell_common_parent()
    parallel_common = _parallel_common_parent()

    # --- run ---
    pr = sub.add_parser("run", parents=[cell_common], help="run a single cell")
    pr.add_argument(
        "--ssh-port",
        type=int,
        default=int(os.environ.get("HOST_SSH_PORT", matrix.DEFAULT_PORT_BASE)),
    )
    pr.add_argument("--workload", default="smoke", choices=sorted(workloads.REGISTRY))
    pr.add_argument(
        "--policy", default=None, help="policy file under the workload's fixture or tools directory"
    )
    pr.add_argument("--kind", default="bughunt", choices=("perf", "bughunt"))
    pr.add_argument("--lsm", default=None, help="lsm chain string passed to the kernel cmdline")
    pr.add_argument("--lvm-pool-max", type=int, default=None)
    pr.add_argument("--nodebug", action="store_true")
    pr.add_argument("--no-kvm", action="store_true", help="treat KVM as not required for this cell")
    mode = pr.add_mutually_exclusive_group()
    mode.add_argument("--headless", action="store_true", help="non-interactive run (default)")
    mode.add_argument(
        "--interactive",
        action="store_true",
        help=(
            "run with the launcher attached to the controlling terminal "
            "(serial console inherits stdio); the VM is still torn down "
            "after the workload"
        ),
    )
    mode.add_argument(
        "--detach-vm",
        action="store_true",
        help="leave the VM up after run; print SSH details and exit",
    )
    pr.add_argument(
        "--tap", action="store_true", help="emit a one-line TAP test point on stdout after the run"
    )
    pr.set_defaults(func=cmd_run)

    # --- matrix ---
    pm = sub.add_parser(
        "matrix", parents=[cell_common, parallel_common], help="run a matrix of cells"
    )
    pm.add_argument("--config", required=True, type=Path, help="matrix YAML/JSON path")
    pm.add_argument(
        "--headless", action="store_true", help="(default) matrix runs are always non-interactive"
    )
    pm.add_argument(
        "--tap", action="store_true", help="emit TAP/KTAP version 13 to stdout after the run"
    )
    pm.add_argument(
        "--junit",
        type=Path,
        default=None,
        help="write a JUnit XML report of the matrix to this path",
    )
    pm.set_defaults(func=cmd_matrix)

    # --- bisect-run ---
    pb = sub.add_parser(
        "bisect-run",
        parents=[cell_common, parallel_common],
        help=(
            "run a single cell (--cell) or matrix (--config) "
            "and exit with KSFT/bisect codes 0/1/125/128"
        ),
    )
    pb_target = pb.add_mutually_exclusive_group(required=True)
    pb_target.add_argument(
        "--cell",
        type=Path,
        help=(
            "single-cell profile YAML/JSON: a flat dict "
            "of profile knobs (workload, kind, policy, ...) "
            "describing the one cell git-bisect will probe"
        ),
    )
    pb_target.add_argument(
        "--config", type=Path, help="matrix YAML/JSON (matrix mode; back-compat)"
    )
    pb.set_defaults(func=cmd_bisect_run)

    # --- image-warm ---
    pw = sub.add_parser("image-warm", help="write the rootfs warm-marker for a given image")
    pw.add_argument("--image", required=True, type=Path)
    pw.add_argument(
        "--marker",
        type=Path,
        default=None,
        help="explicit marker path (default: <image>.warm-marker)",
    )
    pw.set_defaults(func=cmd_image_warm)

    return p
