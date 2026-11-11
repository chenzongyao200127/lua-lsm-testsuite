"""`matrix` subcommand: expand a matrix config and run every cell."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .. import bundle, cell_runner, junit, matrix, run_registry, schemas, tap
from ..ksft import KSFT_FAIL, KSFT_PASS, KSFT_SKIP
from . import common


def build_cell_runner_callback(
    args: argparse.Namespace,
    workspace_root: Path,
    bundle_store: bundle.BundleStore | None = None,
    registry: run_registry.RunRegistry | None = None,
):
    """Return a (cell, artifact_dir, port) -> result.json dict callable.

    The factory closes over the bundle store + run registry so the matrix
    executor can reap registered QEMU children on SIGINT and so first-
    occurrence splats produce a single bundle directory shared across cells.
    Per-test signature stays (cell, artifact_dir, port) -> dict.
    """

    def _runner(cell: matrix.CellSpec, artifact_dir: Path, port: int) -> dict[str, Any]:
        guest_rel = cell_runner.derive_guest_relpath(artifact_dir, workspace_root, None)
        profile = dict(cell.profile)
        profile.setdefault("workload_timeout_s", args.workload_timeout)
        profile["guest_artifact_relpath"] = guest_rel
        if (
            profile.get("kconfig_profile") is None
            and getattr(args, "kconfig_profile", None) is not None
        ):
            profile["kconfig_profile"] = args.kconfig_profile

        policy_paths = common.resolve_policy_paths(
            getattr(args, "share_dir", None),
            profile.get("policy"),
            cell.workload,
        )
        inputs = common.build_cell_inputs(
            args,
            cell_id=cell.cell_id,
            profile=profile,
            workload_name=cell.workload,
            artifact_dir=artifact_dir,
            port=port,
            workspace_root=workspace_root,
            bundle_store=bundle_store,
            registry=registry,
            kvm_required=bool(profile.get("kvm_required", True)),
            policy_paths=policy_paths,
        )
        return cell_runner.run_cell(inputs)

    return _runner


def cmd_matrix(args: argparse.Namespace) -> int:
    common.enforce_supported_host()
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
    distinct_profiles, rc = common.validate_matrix_kconfig_profiles(plan, args.kconfig_profile)
    if rc != 0:
        return rc

    rc = common.maybe_run_kernel_build_for_profiles(args, distinct_profiles)
    if rc != 0:
        return rc

    workspace_root = Path.cwd()
    runs_root = Path(args.runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)
    bundle_store = common.make_bundle_store()
    registry = run_registry.RunRegistry()
    opts = matrix.ExecutorOpts(
        parallel=args.parallel,
        runs_root=runs_root,
        matrix_path=Path(args.config),
        port_base=args.port_base,
        share_dir=args.share_dir,
        registry=registry,
    )
    runner_cb = build_cell_runner_callback(
        args,
        workspace_root,
        bundle_store=bundle_store,
        registry=registry,
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
