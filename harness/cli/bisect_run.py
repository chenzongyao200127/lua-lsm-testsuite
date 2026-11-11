"""`bisect-run` subcommand: KSFT exit codes shaped for `git bisect run`.

Two modes:
    --cell    one cell from a flat profile file -> 0/1/125/128 per
              bisect.exit_code_from_cell_result
    --config  a full matrix (back-compat)      -> bisect.exit_code_from_matrix

The bisect contract (0/1/125/128) is owned by harness.bisect and is
INTENTIONALLY different from the run/matrix KSFT table in harness.ksft;
see the module docstrings there.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .. import bisect, cell_runner, matrix, run_registry, schemas
from . import common
from .matrix_cmd import build_cell_runner_callback


def cmd_bisect_run(args: argparse.Namespace) -> int:
    common.enforce_supported_host()
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
    distinct_profiles, rc = common.validate_matrix_kconfig_profiles(plan, args.kconfig_profile)
    if rc != 0:
        return bisect.KSFT_ABORT

    rc = common.maybe_run_kernel_build_for_profiles(args, distinct_profiles)
    if rc != 0:
        # Build-helper failure in matrix mode: commit is untestable.
        return bisect.KSFT_SKIP

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
    return bisect.exit_code_from_matrix(matrix_doc)


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
                "PyYAML required for .yaml cell profile; install pyyaml or use a .json profile file"
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
            print(
                "error: --build-kernel requires --kconfig-profile or a "
                "kconfig_profile key in the cell profile",
                file=sys.stderr,
            )
            return bisect.KSFT_ABORT
        rc = common.run_kernel_build_profile(args, cell_kconfig)
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
    bundle_store = common.make_bundle_store()
    registry = run_registry.RunRegistry()

    if cell_id_override is None:
        cell_id = cell_runner._make_cell_id(profile_doc, workload_name)
    else:
        cell_id = str(cell_id_override)
    artifact_dir = runs_root / cell_id

    guest_rel = cell_runner.derive_guest_relpath(artifact_dir, workspace_root, None)

    profile_doc.setdefault("workload_timeout_s", args.workload_timeout)
    profile_doc["guest_artifact_relpath"] = guest_rel
    if profile_doc.get("kvm_required") is None:
        profile_doc["kvm_required"] = True

    policy_paths = common.resolve_policy_paths(
        getattr(args, "share_dir", None),
        profile_doc.get("policy"),
        workload_name,
    )

    inputs = common.build_cell_inputs(
        args,
        cell_id=cell_id,
        profile=profile_doc,
        workload_name=workload_name,
        artifact_dir=artifact_dir,
        port=args.port_base,
        workspace_root=workspace_root,
        bundle_store=bundle_store,
        registry=registry,
        kvm_required=bool(profile_doc.get("kvm_required", True)),
        policy_paths=policy_paths,
    )
    try:
        result = cell_runner.run_cell(inputs)
    except Exception as e:
        # Anything that escapes run_cell is by definition a harness internal
        # failure: bisect must abort (128) rather than blame the commit.
        print(f"error: harness raised during bisect single-cell run: {e}", file=sys.stderr)
        return bisect.KSFT_ABORT
    return bisect.exit_code_from_cell_result(result)
