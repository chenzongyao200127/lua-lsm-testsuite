"""Helpers shared by the CLI subcommand modules.

Everything here is plumbing: profile assembly, kernel-build orchestration,
kconfig validation, policy resolution, and the single CellInputs
constructor that `run`, matrix cells, and `bisect-run --cell` all share.
Subcommand bodies live in the sibling modules; the parser in cli.parser.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .. import (
    bundle,
    cell_runner,
    hostenv,
    matrix,
    run_registry,
    schemas,
    ssh,
    workloads,
)
from ..ksft import KSFT_FAIL

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOOLS_DIR = Path(os.environ.get("LUA_LSM_TESTSUITE_TOOLS_DIR", str(REPO_ROOT / "tools")))
DEFAULT_LAUNCHER = Path(os.environ.get("LAUNCHER", str(DEFAULT_TOOLS_DIR / "run_qemu_anolis.sh")))
DEFAULT_RUNS_ROOT = Path(os.environ.get("RUNS_ROOT", "runs"))


def enforce_supported_host() -> None:
    """Refuse macOS at planning time; per-cell KVM skip happens later."""
    host = hostenv.detect()
    hostenv.assert_supported(host)


def profile_from_run_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "kind": args.kind,
        "lsm": args.lsm,
        "lvm_pool_max": args.lvm_pool_max,
        "nodebug": bool(args.nodebug),
        "policy": args.policy,
        "kvm_required": not args.no_kvm,
        "workload_timeout_s": args.workload_timeout,
        "kconfig_profile": args.kconfig_profile,
    }


def make_bundle_store() -> bundle.BundleStore:
    """Build a fresh in-memory BundleStore.

    The store keeps signature->first-bundle-dir bookkeeping in memory; each
    bundle is written under its cell's own artifact_dir (`<art>/bundle/`), so
    no on-disk root is needed at construction time.
    """
    return bundle.BundleStore()


def resolve_policy_paths(
    share_dir: Path | None, policy_name: str | None, workload_name: str
) -> tuple[Path, ...]:
    """Resolve the policy file(s) a cell will register, relative to share_dir.

    Returns a tuple of absolute host paths (suitable for BundleSources.policies).
    When share_dir is None, returns an empty tuple -- the runner can still
    proceed (the bundle just won't carry a policy copy).

    Delegates to workloads.policy_host_path so host-side bundle copies and
    guest-side registration (workloads.policy_guest_path) resolve the same
    file from the same workload spec.
    """
    return workloads.policy_host_path(share_dir, workload_name, policy_name)


def base_env(
    args: argparse.Namespace, ssh_port: int, guest_artifact_relpath: str | None
) -> dict[str, str]:
    env: dict[str, str] = {}
    if args.kernel is not None:
        env["KERNEL_IMG"] = str(args.kernel)
    if args.rootfs is not None:
        env["ROOTFS_IMG"] = str(args.rootfs)
    env["HOST_SSH_PORT"] = str(ssh_port)
    if args.share_dir is not None:
        env["SHARE_DIR"] = str(args.share_dir)
        env["ENABLE_SHARE"] = "1"
    if guest_artifact_relpath:
        env["GUEST_ARTIFACT_RELPATH"] = guest_artifact_relpath
    return env


def ssh_target(args: argparse.Namespace, port: int) -> ssh.SshTarget:
    return ssh.SshTarget(
        host="127.0.0.1",
        port=port,
        user=args.ssh_user,
        key_path=args.ssh_key,
    )


def build_cell_inputs(
    args: argparse.Namespace,
    *,
    cell_id: str,
    profile: dict[str, Any],
    workload_name: str,
    artifact_dir: Path,
    port: int,
    workspace_root: Path,
    bundle_store: bundle.BundleStore | None = None,
    registry: run_registry.RunRegistry | None = None,
    interactive: bool = False,
    kvm_required: bool = True,
    policy_paths: tuple[Path, ...] = (),
) -> cell_runner.CellInputs:
    """The single CellInputs constructor shared by every CLI path.

    `run`, matrix-driven cells, and `bisect-run --cell` build the same
    ~20-kwarg record; this keeps them from drifting apart. The profile must
    already carry `guest_artifact_relpath` (it feeds both the cell record
    and the launch env).
    """
    return cell_runner.CellInputs(
        cell_id=cell_id,
        profile=profile,
        workload_fn=workloads.by_name(workload_name),
        workload_name=workload_name,
        launcher=args.launcher,
        artifact_dir=artifact_dir,
        ssh_target=ssh_target(args, port),
        base_env=base_env(args, port, profile.get("guest_artifact_relpath")),
        boot_timeout_s=args.boot_timeout,
        workload_timeout_s=args.workload_timeout,
        kvm_required=kvm_required,
        guest_artifact_relpath=profile.get("guest_artifact_relpath"),
        workspace_root=workspace_root,
        interactive=interactive,
        bundle_store=bundle_store,
        run_registry=registry,
        kernel_tree=getattr(args, "kernel_tree", None),
        kernel_config_path=getattr(args, "kernel_config", None),
        kernel_config_baseline=getattr(args, "kernel_config_baseline", None),
        rootfs_image=getattr(args, "rootfs", None),
        decode_script=getattr(args, "decode_script", None),
        policy_paths=policy_paths,
    )


# ---------------------------------------------------------------------------
# Kernel build orchestration (--build-kernel).


def maybe_run_kernel_build(args: argparse.Namespace, profile: str | None) -> int:
    """Invoke `enable-debug-kconfig.sh --kernel <tree> --profile <profile>` once.

    Returns 0 on success or when no build was requested. Returns non-zero on
    build failure (the caller should propagate that as a planning-time
    refusal so a broken kernel doesn't get deployed into a long matrix).
    """
    if not getattr(args, "build_kernel", False):
        return 0
    if profile is None:
        print("error: --build-kernel requires --kconfig-profile", file=sys.stderr)
        return KSFT_FAIL
    return run_kernel_build_profile(args, profile)


def run_kernel_build_profile(args: argparse.Namespace, profile: str) -> int:
    """Run `enable-debug-kconfig.sh --kernel <tree> --profile <profile>` once.

    The vendored helper REQUIRES
    `--kernel <dir>`; omitting it fails the helper's own argument check. We
    therefore require `--kernel-tree` whenever `--build-kernel` is requested
    and validate it exists BEFORE the subprocess so a bad tree path fails
    fast with a harness error rather than a cryptic helper error.

    Split out of `maybe_run_kernel_build` so the matrix path can iterate
    over the distinct expanded profiles without retriggering the
    `--build-kernel` guard for each profile.
    """
    if args.debug_kernel is None or not Path(args.debug_kernel).exists():
        print(f"error: --debug-kernel path missing: {args.debug_kernel}", file=sys.stderr)
        return KSFT_FAIL
    helper = Path(args.debug_kernel) / "enable-debug-kconfig.sh"
    if not helper.exists():
        print(f"error: enable-debug-kconfig.sh not found at {helper}", file=sys.stderr)
        return KSFT_FAIL
    kernel_tree = getattr(args, "kernel_tree", None)
    if kernel_tree is None:
        print(
            "error: --build-kernel requires --kernel-tree "
            "(enable-debug-kconfig.sh requires --kernel <dir>)",
            file=sys.stderr,
        )
        return KSFT_FAIL
    kernel_tree = Path(kernel_tree)
    if not kernel_tree.exists():
        print(f"error: --kernel-tree path missing: {kernel_tree}", file=sys.stderr)
        return KSFT_FAIL
    cmd = [str(helper), "--kernel", str(kernel_tree), "--profile", profile]
    try:
        r = subprocess.run(cmd, check=False)
    except OSError as e:
        print(f"error: failed to invoke {helper}: {e}", file=sys.stderr)
        return KSFT_FAIL
    if r.returncode != 0:
        print(f"error: {helper.name} exited rc={r.returncode}", file=sys.stderr)
        return KSFT_FAIL
    return 0


def validate_matrix_kconfig_profiles(
    plan: matrix.MatrixPlan, cli_default: str | None
) -> tuple[list[str], int]:
    """Validate every expanded cell's kconfig_profile.

    Returns (distinct_profiles, rc). `distinct_profiles` is the ordered list of
    unique non-None profiles in encounter order so `--build-kernel` runs the
    helper once per profile without depending on dict ordering on older
    interpreters. `rc` is 0 on success and KSFT_FAIL on the first unknown
    profile.

    The CLI `--kconfig-profile` is treated as a default the matrix can
    override per-cell: a cell that lacks its own profile inherits the CLI
    default but the validator still rejects an invalid CLI default the same
    way it rejects an invalid per-cell value.
    """
    distinct: list[str] = []
    seen: set[str] = set()
    profiles_to_check: list[tuple[str, str | None]] = []
    if cli_default is not None:
        profiles_to_check.append(("--kconfig-profile", cli_default))
    for cell in plan.cells:
        profile_value = cell.profile.get("kconfig_profile")
        if profile_value is None:
            profile_value = cli_default
        profiles_to_check.append((f"cell {cell.cell_id}", profile_value))

    for source, value in profiles_to_check:
        if value is None:
            continue
        try:
            schemas.assert_kconfig_profile(value)
        except schemas.KconfigProfileError as e:
            print(f"error: {source}: {e}", file=sys.stderr)
            return [], KSFT_FAIL
        if value not in seen:
            seen.add(value)
            distinct.append(value)
    return distinct, 0


def maybe_run_kernel_build_for_profiles(args: argparse.Namespace, profiles: list[str]) -> int:
    """For matrix mode: build the kernel once per distinct expanded profile."""
    if not getattr(args, "build_kernel", False):
        return 0
    if not profiles:
        print(
            "error: --build-kernel requires at least one kconfig profile "
            "(set --kconfig-profile or specify kconfig_profile in the matrix)",
            file=sys.stderr,
        )
        return KSFT_FAIL
    for profile in profiles:
        rc = run_kernel_build_profile(args, profile)
        if rc != 0:
            return rc
    return 0
