"""`run` subcommand: single-cell, ad-hoc invocation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import cell_runner, matrix, qemu, schemas, ssh
from ..kernel_cmdline import compose_env
from ..ksft import KSFT_FAIL, KSFT_PASS, KSFT_SKIP
from . import common


def verdict_to_run_exit(verdict: str | None) -> int:
    if verdict is None:
        return KSFT_FAIL
    if schemas.is_pass(verdict):
        return KSFT_PASS
    if schemas.is_skip(verdict):
        return KSFT_SKIP
    return KSFT_FAIL


def cmd_run(args: argparse.Namespace) -> int:
    common.enforce_supported_host()

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

    rc = common.maybe_run_kernel_build(args, args.kconfig_profile)
    if rc != 0:
        return rc

    workspace_root = Path.cwd()
    runs_root = Path(args.runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)

    cell_id = cell_runner._make_cell_id(
        {"kind": args.kind, "workload": args.workload}, args.workload
    )
    artifact_dir = runs_root / cell_id
    guest_rel = cell_runner.derive_guest_relpath(artifact_dir, workspace_root, None)

    profile = common.profile_from_run_args(args)
    profile["guest_artifact_relpath"] = guest_rel

    bundle_store = common.make_bundle_store()
    policy_paths = common.resolve_policy_paths(args.share_dir, args.policy, args.workload)

    inputs = common.build_cell_inputs(
        args,
        cell_id=cell_id,
        profile=profile,
        workload_name=args.workload,
        artifact_dir=artifact_dir,
        port=args.ssh_port,
        workspace_root=workspace_root,
        bundle_store=bundle_store,
        interactive=bool(args.interactive),
        kvm_required=not args.no_kvm,
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

    return verdict_to_run_exit(result.get("verdict"))


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
        env = compose_env(dict(inputs.profile), inputs.base_env)
    except Exception as e:
        print(f"error: cmdline composition failed: {e}", file=sys.stderr)
        return KSFT_FAIL
    (artifact_dir / "extra-cmdline.txt").write_text(env["EXTRA_CMDLINE"] + "\n")
    (artifact_dir / "qemu-cmdline.txt").write_text(
        qemu.render_launch_command(inputs.launcher, env) + "\n",
    )

    try:
        handle = qemu.spawn(
            inputs.launcher,
            env,
            artifact_dir / "serial.log",
            interactive=inputs.interactive,
        )
    except qemu.QemuLaunchError as e:
        print(f"error: qemu launch failed: {e}", file=sys.stderr)
        return KSFT_FAIL

    if not ssh.wait_for_ssh(inputs.ssh_target, timeout_s=inputs.boot_timeout_s):
        print(f"error: ssh did not come up within {inputs.boot_timeout_s:.0f}s", file=sys.stderr)
        # Leave the VM running so the user can investigate why ssh failed.
        print(f"pid={handle.proc.pid}\nssh_port={inputs.ssh_target.port}")
        return KSFT_FAIL

    print(f"pid={handle.proc.pid}\nssh_port={inputs.ssh_target.port}")
    return KSFT_PASS
