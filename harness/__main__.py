"""CLI entrypoint for the harness: `python3 -m harness <subcommand>`.

Subcommands:
    run          single-cell run, ad-hoc invocation
    matrix       expand a matrix YAML/JSON and run every cell
    bisect-run   alias for matrix that maps the matrix verdict to a KSFT
                 exit code suitable for `git bisect run`
    image-warm   write the rootfs warm-marker file once

The CLI does not implement boot/shell logic itself: it constructs a
CellInputs / MatrixPlan and hands it to harness.cell_runner.run_cell or
harness.matrix.run_matrix. This keeps the surface area small and the
orchestration testable -- the integration tests in tests/test_main_cli.py
mock qemu.spawn / ssh.run / ssh.wait_for_ssh and assert on the dispatcher.

Refusal at planning time:
    - Darwin host -> hostenv.assert_supported raises before any runs/ dir.
    - --detach-vm in matrix/bisect-run -> argparse rejects it (interactive
      mode is per-cell only).
    - SHARE_DIR missing the entries required by the selected workloads.

The CLI's exit code matters:
    run             0 on pass, 1 on any non-pass non-skip; KSFT 4 on skip.
    matrix          0 on pass, 1 on any failed cell; KSFT 4 on all-skip.
    bisect-run      bisect.exit_code_from_matrix (0/1/125/128).
    image-warm      0 on success, 1 on missing image / write failure.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import (
    bisect, bundle, cell_runner, cmdline, hostenv, matrix, preflight, qemu,
    run_registry, schemas, ssh, tap, junit, workloads,
)
import subprocess

# KSFT exit codes used by `run` and `matrix` (bisect-run uses harness.bisect).
KSFT_PASS = 0
KSFT_FAIL = 1
KSFT_SKIP = 4

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TOOLS_DIR = Path(os.environ.get("LUA_LSM_TESTSUITE_TOOLS_DIR",
                                         str(REPO_ROOT / "tools")))
DEFAULT_LAUNCHER = Path(os.environ.get("LAUNCHER",
                                        str(DEFAULT_TOOLS_DIR / "run_qemu_anolis.sh")))
DEFAULT_RUNS_ROOT = Path(os.environ.get("RUNS_ROOT", "runs"))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 -m harness",
        description="Out-of-tree QEMU matrix harness for the Linux Lua LSM",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # --- run ---
    pr = sub.add_parser("run", help="run a single cell")
    pr.add_argument("--kernel", required=False, type=Path, help="bzImage path")
    pr.add_argument("--rootfs", required=False, type=Path, help="rootfs image path")
    pr.add_argument("--launcher", type=Path, default=DEFAULT_LAUNCHER)
    pr.add_argument("--ssh-key", type=Path, default=Path(os.environ.get(
        "SSH_KEY", os.path.expanduser("~/.ssh/id_rsa"))))
    pr.add_argument("--ssh-port", type=int, default=int(os.environ.get(
        "HOST_SSH_PORT", matrix.DEFAULT_PORT_BASE)))
    pr.add_argument("--ssh-user", default=os.environ.get("SSH_USER", "root"))
    pr.add_argument("--share-dir", type=Path,
                    default=Path(os.environ["SHARE_DIR"]) if os.environ.get("SHARE_DIR") else None)
    pr.add_argument("--workload", default="smoke",
                    choices=sorted(workloads.REGISTRY))
    pr.add_argument("--policy", default=None,
                    help="policy file under the workload's fixture or tools directory")
    pr.add_argument("--kind", default="bughunt", choices=("perf", "bughunt"))
    pr.add_argument("--lsm", default=None,
                    help="lsm chain string passed to the kernel cmdline")
    pr.add_argument("--lvm-pool-max", type=int, default=None)
    pr.add_argument("--nodebug", action="store_true")
    pr.add_argument("--no-kvm", action="store_true",
                    help="treat KVM as not required for this cell")
    pr.add_argument("--boot-timeout", type=float, default=180.0)
    pr.add_argument("--workload-timeout", type=float, default=600.0)
    pr.add_argument("--runs-root", type=Path, default=DEFAULT_RUNS_ROOT)
    mode = pr.add_mutually_exclusive_group()
    mode.add_argument("--headless", action="store_true",
                      help="non-interactive run (default)")
    mode.add_argument("--interactive", action="store_true",
                      help=("run with the launcher attached to the controlling terminal "
                            "(serial console inherits stdio); the VM is still torn down "
                            "after the workload"))
    mode.add_argument("--detach-vm", action="store_true",
                      help="leave the VM up after run; print SSH details and exit")
    pr.add_argument("--tap", action="store_true",
                    help="emit a one-line TAP test point on stdout after the run")
    pr.add_argument("--kconfig-profile",
                    choices=sorted(schemas.VALID_KCONFIG_PROFILES),
                    default=None,
                    help="kconfig profile (standard|full); recorded in result.json")
    pr.add_argument("--build-kernel", action="store_true",
                    help=("invoke enable-debug-kconfig.sh --kernel <tree> "
                          "--profile <X> before launch (requires --kernel-tree)"))
    pr.add_argument("--kernel-tree", type=Path, default=None,
                    help="kernel source tree path (used for build + bundle)")
    pr.add_argument("--debug-kernel", type=Path, default=DEFAULT_TOOLS_DIR,
                    help="directory containing host build helpers")
    pr.add_argument("--kernel-config", type=Path, default=None,
                    help="kernel .config path to record in the bundle")
    pr.add_argument("--kernel-config-baseline", type=Path, default=None,
                    help="baseline .config to diff the active config against")
    pr.add_argument("--decode-script", type=Path, default=None,
                    help="path to scripts/decode_stacktrace.sh for bundle decode")

    # --- matrix ---
    pm = sub.add_parser("matrix", help="run a matrix of cells")
    pm.add_argument("--config", required=True, type=Path, help="matrix YAML/JSON path")
    pm.add_argument("--kernel", required=False, type=Path)
    pm.add_argument("--rootfs", required=False, type=Path)
    pm.add_argument("--launcher", type=Path, default=DEFAULT_LAUNCHER)
    pm.add_argument("--ssh-key", type=Path, default=Path(os.environ.get(
        "SSH_KEY", os.path.expanduser("~/.ssh/id_rsa"))))
    pm.add_argument("--ssh-user", default=os.environ.get("SSH_USER", "root"))
    pm.add_argument("--share-dir", type=Path,
                    default=Path(os.environ["SHARE_DIR"]) if os.environ.get("SHARE_DIR") else None)
    pm.add_argument("--port-base", type=int, default=matrix.DEFAULT_PORT_BASE)
    pm.add_argument("--parallel", type=int, default=1)
    pm.add_argument("--runs-root", type=Path, default=DEFAULT_RUNS_ROOT)
    pm.add_argument("--boot-timeout", type=float, default=180.0)
    pm.add_argument("--workload-timeout", type=float, default=600.0)
    pm.add_argument("--headless", action="store_true",
                    help="(default) matrix runs are always non-interactive")
    pm.add_argument("--tap", action="store_true",
                    help="emit TAP/KTAP version 13 to stdout after the run")
    pm.add_argument("--junit", type=Path, default=None,
                    help="write a JUnit XML report of the matrix to this path")
    pm.add_argument("--kconfig-profile",
                    choices=sorted(schemas.VALID_KCONFIG_PROFILES),
                    default=None,
                    help="kconfig profile (standard|full); recorded per cell")
    pm.add_argument("--build-kernel", action="store_true",
                    help=("invoke enable-debug-kconfig.sh --kernel <tree> "
                          "--profile <X> once per distinct profile before "
                          "scheduling (requires --kernel-tree)"))
    pm.add_argument("--kernel-tree", type=Path, default=None)
    pm.add_argument("--debug-kernel", type=Path, default=DEFAULT_TOOLS_DIR)
    pm.add_argument("--kernel-config", type=Path, default=None)
    pm.add_argument("--kernel-config-baseline", type=Path, default=None)
    pm.add_argument("--decode-script", type=Path, default=None)

    # --- bisect-run ---
    pb = sub.add_parser("bisect-run",
                        help=("run a single cell (--cell) or matrix (--config) "
                              "and exit with KSFT/bisect codes 0/1/125/128"))
    pb_target = pb.add_mutually_exclusive_group(required=True)
    pb_target.add_argument("--cell", type=Path,
                           help=("single-cell profile YAML/JSON: a flat dict "
                                 "of profile knobs (workload, kind, policy, ...) "
                                 "describing the one cell git-bisect will probe"))
    pb_target.add_argument("--config", type=Path,
                           help="matrix YAML/JSON (matrix mode; back-compat)")
    pb.add_argument("--kernel", required=False, type=Path)
    pb.add_argument("--rootfs", required=False, type=Path)
    pb.add_argument("--launcher", type=Path, default=DEFAULT_LAUNCHER)
    pb.add_argument("--ssh-key", type=Path, default=Path(os.environ.get(
        "SSH_KEY", os.path.expanduser("~/.ssh/id_rsa"))))
    pb.add_argument("--ssh-user", default=os.environ.get("SSH_USER", "root"))
    pb.add_argument("--share-dir", type=Path,
                    default=Path(os.environ["SHARE_DIR"]) if os.environ.get("SHARE_DIR") else None)
    pb.add_argument("--port-base", type=int, default=matrix.DEFAULT_PORT_BASE)
    pb.add_argument("--parallel", type=int, default=1)
    pb.add_argument("--runs-root", type=Path, default=DEFAULT_RUNS_ROOT)
    pb.add_argument("--boot-timeout", type=float, default=180.0)
    pb.add_argument("--workload-timeout", type=float, default=600.0)
    pb.add_argument("--kconfig-profile",
                    choices=sorted(schemas.VALID_KCONFIG_PROFILES),
                    default=None)
    pb.add_argument("--build-kernel", action="store_true")
    pb.add_argument("--kernel-tree", type=Path, default=None)
    pb.add_argument("--debug-kernel", type=Path, default=DEFAULT_TOOLS_DIR)
    pb.add_argument("--kernel-config", type=Path, default=None)
    pb.add_argument("--kernel-config-baseline", type=Path, default=None)
    pb.add_argument("--decode-script", type=Path, default=None)

    # --- image-warm ---
    pw = sub.add_parser("image-warm",
                        help="write the rootfs warm-marker for a given image")
    pw.add_argument("--image", required=True, type=Path)
    pw.add_argument("--marker", type=Path, default=None,
                    help="explicit marker path (default: <image>.warm-marker)")

    return p


def _enforce_supported_host() -> None:
    """Refuse macOS at planning time; per-cell KVM skip happens later."""
    host = hostenv.detect()
    hostenv.assert_supported(host)


# ---------------------------------------------------------------------------
# Helpers shared between `run` and matrix-driven cells.

def _profile_from_run_args(args: argparse.Namespace) -> dict[str, Any]:
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


def _maybe_run_kernel_build(args: argparse.Namespace, profile: str | None) -> int:
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
    return _run_kernel_build_profile(args, profile)


def _run_kernel_build_profile(args: argparse.Namespace, profile: str) -> int:
    """Run `enable-debug-kconfig.sh --kernel <tree> --profile <profile>` once.

    The vendored helper REQUIRES
    `--kernel <dir>`; omitting it fails the helper's own argument check. We
    therefore require `--kernel-tree` whenever `--build-kernel` is requested
    and validate it exists BEFORE the subprocess so a bad tree path fails
    fast with a harness error rather than a cryptic helper error.

    Split out of `_maybe_run_kernel_build` so the matrix path can iterate
    over the distinct expanded profiles without retriggering the
    `--build-kernel` guard for each profile.
    """
    if args.debug_kernel is None or not Path(args.debug_kernel).exists():
        print(f"error: --debug-kernel path missing: {args.debug_kernel}",
              file=sys.stderr)
        return KSFT_FAIL
    helper = Path(args.debug_kernel) / "enable-debug-kconfig.sh"
    if not helper.exists():
        print(f"error: enable-debug-kconfig.sh not found at {helper}",
              file=sys.stderr)
        return KSFT_FAIL
    kernel_tree = getattr(args, "kernel_tree", None)
    if kernel_tree is None:
        print("error: --build-kernel requires --kernel-tree "
              "(enable-debug-kconfig.sh requires --kernel <dir>)",
              file=sys.stderr)
        return KSFT_FAIL
    kernel_tree = Path(kernel_tree)
    if not kernel_tree.exists():
        print(f"error: --kernel-tree path missing: {kernel_tree}",
              file=sys.stderr)
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


def _validate_matrix_kconfig_profiles(plan: matrix.MatrixPlan,
                                      cli_default: str | None) -> tuple[list[str], int]:
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


def _maybe_run_kernel_build_for_profiles(args: argparse.Namespace,
                                         profiles: list[str]) -> int:
    """For matrix mode: build the kernel once per distinct expanded profile."""
    if not getattr(args, "build_kernel", False):
        return 0
    if not profiles:
        print("error: --build-kernel requires at least one kconfig profile "
              "(set --kconfig-profile or specify kconfig_profile in the matrix)",
              file=sys.stderr)
        return KSFT_FAIL
    for profile in profiles:
        rc = _run_kernel_build_profile(args, profile)
        if rc != 0:
            return rc
    return 0


def _make_bundle_store() -> bundle.BundleStore:
    """Build a fresh in-memory BundleStore.

    The store keeps signature->first-bundle-dir bookkeeping in memory; each
    bundle is written under its cell's own artifact_dir (`<art>/bundle/`), so
    no on-disk root is needed at construction time.
    """
    return bundle.BundleStore()


def _resolve_policy_paths(share_dir: Path | None, policy_name: str | None,
                          workload_name: str) -> tuple[Path, ...]:
    """Resolve the policy file(s) a cell will register, relative to share_dir.

    Returns a tuple of absolute host paths (suitable for BundleSources.policies).
    When share_dir is None, returns an empty tuple -- the runner can still
    proceed (the bundle just won't carry a policy copy).

    Delegates to workloads.policy_host_path so host-side bundle copies and
    guest-side registration (workloads.policy_guest_path) resolve the same
    file from the same workload spec.
    """
    return workloads.policy_host_path(share_dir, workload_name, policy_name)


def _base_env(args: argparse.Namespace,
              ssh_port: int,
              guest_artifact_relpath: str | None) -> dict[str, str]:
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


def _ssh_target(args: argparse.Namespace, port: int) -> ssh.SshTarget:
    return ssh.SshTarget(
        host="127.0.0.1",
        port=port,
        user=args.ssh_user,
        key_path=args.ssh_key,
    )


def _verdict_to_run_exit(verdict: str | None) -> int:
    if verdict is None:
        return KSFT_FAIL
    if schemas.is_pass(verdict):
        return KSFT_PASS
    if schemas.is_skip(verdict):
        return KSFT_SKIP
    return KSFT_FAIL


# ---------------------------------------------------------------------------
# Subcommand bodies.

def _cmd_run(args: argparse.Namespace) -> int:
    _enforce_supported_host()

    # Refuse unknown kconfig profiles BEFORE creating any artifact dir.
    try:
        schemas.assert_kconfig_profile(args.kconfig_profile)
    except schemas.KconfigProfileError as e:
        print(f"error: {e}", file=sys.stderr)
        return KSFT_FAIL

    if args.share_dir is not None:
        try:
            matrix.assert_share_dir(
                args.share_dir,
                matrix.required_share_entries([args.workload]),
            )
        except matrix.ShareDirError as e:
            print(f"error: {e}", file=sys.stderr)
            return KSFT_FAIL

    rc = _maybe_run_kernel_build(args, args.kconfig_profile)
    if rc != 0:
        return rc

    workspace_root = Path.cwd()
    runs_root = Path(args.runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)

    cell_id = cell_runner._make_cell_id({"kind": args.kind, "workload": args.workload}, args.workload)
    artifact_dir = runs_root / cell_id
    guest_rel = None
    try:
        guest_rel = str(artifact_dir.resolve().relative_to(workspace_root.resolve()))
    except ValueError:
        guest_rel = None

    profile = _profile_from_run_args(args)
    profile["guest_artifact_relpath"] = guest_rel

    bundle_store = _make_bundle_store()
    policy_paths = _resolve_policy_paths(args.share_dir, args.policy, args.workload)

    inputs = cell_runner.CellInputs(
        cell_id=cell_id,
        profile=profile,
        workload_fn=workloads.by_name(args.workload),
        workload_name=args.workload,
        launcher=args.launcher,
        artifact_dir=artifact_dir,
        ssh_target=_ssh_target(args, args.ssh_port),
        base_env=_base_env(args, args.ssh_port, guest_rel),
        boot_timeout_s=args.boot_timeout,
        workload_timeout_s=args.workload_timeout,
        kvm_required=not args.no_kvm,
        guest_artifact_relpath=guest_rel,
        workspace_root=workspace_root,
        interactive=bool(args.interactive),
        bundle_store=bundle_store,
        kernel_tree=args.kernel_tree,
        kernel_config_path=args.kernel_config,
        kernel_config_baseline=args.kernel_config_baseline,
        rootfs_image=args.rootfs,
        decode_script=args.decode_script,
        policy_paths=policy_paths,
    )

    if args.detach_vm:
        return _run_cell_detached(inputs, artifact_dir)

    result = cell_runner.run_cell(inputs)

    if args.tap:
        verdict = result.get("verdict") or "no-verdict"
        klass = schemas.VERDICT_CLASSIFICATION.get(verdict, "fail")
        if klass == "pass":
            print(f"ok 1 - {cell_id}")
        elif klass == "skip":
            print(f"ok 1 - {cell_id} # SKIP {verdict}")
        else:
            print(f"not ok 1 - {cell_id}")
            print(f"    # verdict: {verdict}")

    return _verdict_to_run_exit(result.get("verdict"))


def _run_cell_detached(inputs: cell_runner.CellInputs, artifact_dir: Path) -> int:
    """Compose env, write cell.json, spawn QEMU, wait SSH, print pid+port, return.

    Detach mode is the dev-tool variant of `run`: it drops the user back at
    the shell with a live VM they can SSH into. No workload is run, no
    result.json is finalised, and qemu is NOT torn down. The returned pid
    and ssh_port are the contract a wrapper script (or the user) uses to
    interact with or eventually reap the VM.
    """
    artifact_dir.mkdir(parents=True, exist_ok=True)
    cell_runner._write_cell_record(artifact_dir, inputs.cell_id, inputs)

    try:
        env = cmdline.compose_env(dict(inputs.profile), inputs.base_env)
    except Exception as e:
        print(f"error: cmdline composition failed: {e}", file=sys.stderr)
        return KSFT_FAIL
    (artifact_dir / "extra-cmdline.txt").write_text(env["EXTRA_CMDLINE"] + "\n")
    (artifact_dir / "qemu-cmdline.txt").write_text(
        qemu.render_launch_command(inputs.launcher, env) + "\n",
    )

    try:
        handle = qemu.spawn(
            inputs.launcher, env, artifact_dir / "serial.log",
            interactive=inputs.interactive,
        )
    except qemu.QemuLaunchError as e:
        print(f"error: qemu launch failed: {e}", file=sys.stderr)
        return KSFT_FAIL

    if not ssh.wait_for_ssh(inputs.ssh_target, timeout_s=inputs.boot_timeout_s):
        print(f"error: ssh did not come up within {inputs.boot_timeout_s:.0f}s",
              file=sys.stderr)
        # Leave the VM running so the user can investigate why ssh failed.
        print(f"pid={handle.proc.pid}\nssh_port={inputs.ssh_target.port}")
        return KSFT_FAIL

    print(f"pid={handle.proc.pid}\nssh_port={inputs.ssh_target.port}")
    return KSFT_PASS


def _build_cell_runner_callback(args: argparse.Namespace, workspace_root: Path,
                                bundle_store: bundle.BundleStore | None = None,
                                registry: run_registry.RunRegistry | None = None):
    """Return a (cell, artifact_dir, port) -> result.json dict callable.

    The factory closes over the bundle store + run registry so the matrix
    executor can reap registered QEMU children on SIGINT and so first-
    occurrence splats produce a single bundle directory shared across cells.
    Per-test signature stays (cell, artifact_dir, port) -> dict.
    """

    def _runner(cell: matrix.CellSpec, artifact_dir: Path, port: int) -> dict[str, Any]:
        guest_rel = None
        try:
            guest_rel = str(artifact_dir.resolve().relative_to(workspace_root.resolve()))
        except ValueError:
            guest_rel = None
        profile = dict(cell.profile)
        profile.setdefault("workload_timeout_s", args.workload_timeout)
        profile["guest_artifact_relpath"] = guest_rel
        if profile.get("kconfig_profile") is None and getattr(args, "kconfig_profile", None) is not None:
            profile["kconfig_profile"] = args.kconfig_profile

        policy_paths = _resolve_policy_paths(
            getattr(args, "share_dir", None),
            profile.get("policy"),
            cell.workload,
        )
        inputs = cell_runner.CellInputs(
            cell_id=cell.cell_id,
            profile=profile,
            workload_fn=workloads.by_name(cell.workload),
            workload_name=cell.workload,
            launcher=args.launcher,
            artifact_dir=artifact_dir,
            ssh_target=_ssh_target(args, port),
            base_env=_base_env(args, port, guest_rel),
            boot_timeout_s=args.boot_timeout,
            workload_timeout_s=args.workload_timeout,
            kvm_required=bool(profile.get("kvm_required", True)),
            guest_artifact_relpath=guest_rel,
            workspace_root=workspace_root,
            bundle_store=bundle_store,
            run_registry=registry,
            kernel_tree=getattr(args, "kernel_tree", None),
            kernel_config_path=getattr(args, "kernel_config", None),
            kernel_config_baseline=getattr(args, "kernel_config_baseline", None),
            rootfs_image=getattr(args, "rootfs", None),
            decode_script=getattr(args, "decode_script", None),
            policy_paths=policy_paths,
        )
        return cell_runner.run_cell(inputs)

    return _runner


def _cmd_matrix(args: argparse.Namespace) -> int:
    _enforce_supported_host()
    # Expand and validate the matrix BEFORE creating runs/ or invoking the
    # kernel build helper: an invalid kconfig profile in any expanded cell
    # must fail before any artifact directory exists, and --build-kernel must
    # know every distinct profile so it runs the helper once per profile.
    plan = matrix.plan_from_file(Path(args.config))
    if args.share_dir is not None:
        try:
            matrix.assert_share_dir(
                args.share_dir,
                matrix.required_share_entries([cell.workload for cell in plan.cells]),
            )
        except matrix.ShareDirError as e:
            print(f"error: {e}", file=sys.stderr)
            return KSFT_FAIL
    distinct_profiles, rc = _validate_matrix_kconfig_profiles(plan, args.kconfig_profile)
    if rc != 0:
        return rc

    rc = _maybe_run_kernel_build_for_profiles(args, distinct_profiles)
    if rc != 0:
        return rc

    workspace_root = Path.cwd()
    runs_root = Path(args.runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)
    bundle_store = _make_bundle_store()
    registry = run_registry.RunRegistry()
    opts = matrix.ExecutorOpts(
        parallel=args.parallel,
        runs_root=runs_root,
        matrix_path=Path(args.config),
        port_base=args.port_base,
        share_dir=args.share_dir,
        registry=registry,
    )
    runner_cb = _build_cell_runner_callback(
        args, workspace_root, bundle_store=bundle_store, registry=registry,
    )
    matrix_doc = matrix.run_matrix(plan, opts, runner_cb)

    if args.tap:
        sys.stdout.write(tap.emit_tap(matrix_doc))

    if args.junit is not None:
        args.junit.parent.mkdir(parents=True, exist_ok=True)
        args.junit.write_text(junit.emit_junit(matrix_doc))

    totals = matrix_doc.get("totals", {})
    aggregate = schemas.aggregate_verdict(totals)
    if aggregate == "pass":
        return KSFT_PASS
    if aggregate == "fail":
        return KSFT_FAIL
    if aggregate == "skip-all":
        return KSFT_SKIP
    return KSFT_FAIL


def _load_cell_profile(path: Path) -> dict[str, Any]:
    """Load a single-cell profile YAML/JSON for `bisect-run --cell`.

    The profile file is a flat dict of profile knobs (workload, kind,
    policy, lvm_pool_max, kconfig_profile, ...). Optional top-level
    `cell_id` overrides the auto-generated id; otherwise the basename of
    the file (without suffix) is used. This shape mirrors a single CellSpec
    so a developer can copy one matrix-expanded cell into a YAML file and
    feed it to bisect-run unchanged.
    """
    text = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "PyYAML required for .yaml cell profile; install pyyaml "
                "or use a .json profile file"
            ) from e
        doc = yaml.safe_load(text) or {}
    else:
        doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError(f"cell profile {path} must be a mapping at the top level")
    return doc


def _cmd_bisect_run_single_cell(args: argparse.Namespace) -> int:
    """Run one cell and exit with KSFT 0/1/125/128 per bisect.exit_code_from_cell_result."""
    cell_path = Path(args.cell)
    try:
        profile_doc = _load_cell_profile(cell_path)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as e:
        print(f"error: cannot load cell profile {cell_path}: {e}", file=sys.stderr)
        return bisect.KSFT_ABORT

    workload_name = str(profile_doc.pop("workload", "smoke"))
    cell_id_override = profile_doc.pop("cell_id", None)
    cell_kconfig = profile_doc.get("kconfig_profile") or args.kconfig_profile
    try:
        schemas.assert_kconfig_profile(cell_kconfig)
    except schemas.KconfigProfileError as e:
        print(f"error: {e}", file=sys.stderr)
        return bisect.KSFT_ABORT

    if cell_kconfig is not None:
        profile_doc["kconfig_profile"] = cell_kconfig

    # --build-kernel: invoke the helper exactly once for the cell's profile.
    if getattr(args, "build_kernel", False):
        if cell_kconfig is None:
            print("error: --build-kernel requires --kconfig-profile or a "
                  "kconfig_profile key in the cell profile", file=sys.stderr)
            return bisect.KSFT_ABORT
        rc = _run_kernel_build_profile(args, cell_kconfig)
        if rc != 0:
            # Helper-side build failures mean the commit is untestable;
            # map to bisect skip (125) rather than fail (1) so bisect
            # continues to other commits instead of blaming this one.
            return bisect.KSFT_SKIP

    if args.share_dir is not None:
        try:
            matrix.assert_share_dir(
                args.share_dir,
                matrix.required_share_entries([workload_name]),
            )
        except matrix.ShareDirError as e:
            print(f"error: {e}", file=sys.stderr)
            return bisect.KSFT_ABORT

    workspace_root = Path.cwd()
    runs_root = Path(args.runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)
    bundle_store = _make_bundle_store()
    registry = run_registry.RunRegistry()

    if cell_id_override is None:
        cell_id = cell_runner._make_cell_id(profile_doc, workload_name)
    else:
        cell_id = str(cell_id_override)
    artifact_dir = runs_root / cell_id

    guest_rel = None
    try:
        guest_rel = str(artifact_dir.resolve().relative_to(workspace_root.resolve()))
    except ValueError:
        guest_rel = None

    profile_doc.setdefault("workload_timeout_s", args.workload_timeout)
    profile_doc["guest_artifact_relpath"] = guest_rel
    if profile_doc.get("kvm_required") is None:
        profile_doc["kvm_required"] = True

    policy_paths = _resolve_policy_paths(
        getattr(args, "share_dir", None),
        profile_doc.get("policy"),
        workload_name,
    )

    inputs = cell_runner.CellInputs(
        cell_id=cell_id,
        profile=profile_doc,
        workload_fn=workloads.by_name(workload_name),
        workload_name=workload_name,
        launcher=args.launcher,
        artifact_dir=artifact_dir,
        ssh_target=_ssh_target(args, args.port_base),
        base_env=_base_env(args, args.port_base, guest_rel),
        boot_timeout_s=args.boot_timeout,
        workload_timeout_s=args.workload_timeout,
        kvm_required=bool(profile_doc.get("kvm_required", True)),
        guest_artifact_relpath=guest_rel,
        workspace_root=workspace_root,
        bundle_store=bundle_store,
        run_registry=registry,
        kernel_tree=getattr(args, "kernel_tree", None),
        kernel_config_path=getattr(args, "kernel_config", None),
        kernel_config_baseline=getattr(args, "kernel_config_baseline", None),
        rootfs_image=getattr(args, "rootfs", None),
        decode_script=getattr(args, "decode_script", None),
        policy_paths=policy_paths,
    )
    try:
        result = cell_runner.run_cell(inputs)
    except Exception as e:
        # Anything that escapes run_cell is by definition a harness internal
        # failure: bisect must abort (128) rather than blame the commit.
        print(f"error: harness raised during bisect single-cell run: {e}",
              file=sys.stderr)
        return bisect.KSFT_ABORT
    return bisect.exit_code_from_cell_result(result)


def _cmd_bisect_run(args: argparse.Namespace) -> int:
    _enforce_supported_host()
    if getattr(args, "cell", None) is not None:
        return _cmd_bisect_run_single_cell(args)

    plan = matrix.plan_from_file(Path(args.config))
    if args.share_dir is not None:
        try:
            matrix.assert_share_dir(
                args.share_dir,
                matrix.required_share_entries([cell.workload for cell in plan.cells]),
            )
        except matrix.ShareDirError as e:
            print(f"error: {e}", file=sys.stderr)
            return bisect.KSFT_ABORT
    distinct_profiles, rc = _validate_matrix_kconfig_profiles(plan, args.kconfig_profile)
    if rc != 0:
        return bisect.KSFT_ABORT

    rc = _maybe_run_kernel_build_for_profiles(args, distinct_profiles)
    if rc != 0:
        # Build-helper failure in matrix mode: commit is untestable.
        return bisect.KSFT_SKIP

    workspace_root = Path.cwd()
    runs_root = Path(args.runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)
    bundle_store = _make_bundle_store()
    registry = run_registry.RunRegistry()
    opts = matrix.ExecutorOpts(
        parallel=args.parallel,
        runs_root=runs_root,
        matrix_path=Path(args.config),
        port_base=args.port_base,
        share_dir=args.share_dir,
        registry=registry,
    )
    runner_cb = _build_cell_runner_callback(
        args, workspace_root, bundle_store=bundle_store, registry=registry,
    )
    matrix_doc = matrix.run_matrix(plan, opts, runner_cb)
    return bisect.exit_code_from_matrix(matrix_doc)


def _cmd_image_warm(args: argparse.Namespace) -> int:
    image = Path(args.image)
    if not image.exists():
        print(f"error: image not found: {image}", file=sys.stderr)
        return KSFT_FAIL
    marker = Path(args.marker) if args.marker else preflight.default_warm_marker(image)
    try:
        marker.write_text(f"warm: {image}\n")
    except OSError as e:
        print(f"error: cannot write {marker}: {e}", file=sys.stderr)
        return KSFT_FAIL
    print(f"warm-marker: {marker}")
    return KSFT_PASS


# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return _cmd_run(args)
    if args.cmd == "matrix":
        return _cmd_matrix(args)
    if args.cmd == "bisect-run":
        return _cmd_bisect_run(args)
    if args.cmd == "image-warm":
        return _cmd_image_warm(args)
    parser.print_help(sys.stderr)
    return KSFT_FAIL


if __name__ == "__main__":
    try:
        sys.exit(main())
    except hostenv.UnsupportedHostError as e:
        print(e.message, file=sys.stderr)
        sys.exit(2)
