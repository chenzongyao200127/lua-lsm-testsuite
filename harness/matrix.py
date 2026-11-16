"""Matrix planner and parallel executor.

A matrix is a list of cell profiles, expanded from a YAML config file. The
planner expands `axis` definitions into the full Cartesian product, applies
exclude rules, and yields concrete cell profiles. The executor runs the
expanded matrix with bounded parallelism, isolates each cell into its own
artifact directory, and aggregates per-cell result.json into a matrix.json.

The minimal smoke matrix (DEC-5: 32 cells) is shipped at configs/smoke.yaml;
larger perf matrices live alongside it. The planner is intentionally
schema-light: anything beyond the documented axes / exclude rules is passed
through into the cell profile dict, so a workload can read profile-specific
knobs without the planner needing to know about them.
"""

from __future__ import annotations

import concurrent.futures as cf
import contextlib
import datetime as _dt
import itertools
import json
import re
import signal
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import run_registry, schemas, workloads


@dataclass
class CellSpec:
    """A single, fully-resolved cell profile.

    `profile` carries the merged axis values and any base-level keys (workload,
    kvm_required, etc.). `cell_id` is the harness's stable id used as the
    artifact-directory prefix.
    """

    cell_id: str
    profile: dict[str, Any]
    workload: str

    def to_dict(self) -> dict[str, Any]:
        return {"cell_id": self.cell_id, "profile": dict(self.profile), "workload": self.workload}


def _utc_now_id() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(value: Any) -> str:
    """Filesystem-safe rendering of an axis value.

    Comma chains and slashes turn into underscores so the cell_id stays a
    single legible path component.
    """
    s = str(value)
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def expand(matrix_doc: Mapping[str, Any]) -> list[CellSpec]:
    """Expand a matrix YAML doc into concrete CellSpec entries.

    Recognised top-level keys:
    - `name`: matrix name (informational, used in cell_id prefix).
    - `defaults`: dict of profile keys applied to every cell unless overridden.
    - `axes`: dict of axis_name -> list of values; the cartesian product yields
      one cell per combination.
    - `exclude`: list of dicts; any cell matching all keys of an exclude rule
      (after axis expansion) is dropped.
    - `workload`: default workload name; can be overridden per-axis-row by an
      axis named `workload`.

    `cell_id` is built as `<matrix_name>-<axis-summary>` where `<axis-summary>`
    is a deterministic concat of axis values.
    """
    name = str(matrix_doc.get("name", "matrix"))
    defaults = dict(matrix_doc.get("defaults", {}))
    axes = matrix_doc.get("axes", {}) or {}
    excludes = list(matrix_doc.get("exclude", []) or [])
    default_workload = str(matrix_doc.get("workload", defaults.get("workload", "smoke")))

    if not axes:
        spec = CellSpec(
            cell_id=f"{name}-default",
            profile=dict(defaults),
            workload=default_workload,
        )
        return [spec] if not _matches_any(spec.profile, excludes) else []

    axis_keys = sorted(axes.keys())
    axis_values = [axes[k] for k in axis_keys]

    out: list[CellSpec] = []
    for combo in itertools.product(*axis_values):
        profile = dict(defaults)
        for key, value in zip(axis_keys, combo):
            profile[key] = value
        if _matches_any(profile, excludes):
            continue
        workload = str(profile.get("workload", default_workload))
        summary = "-".join(_slug(profile[k]) for k in axis_keys)
        cell_id = f"{name}-{summary}"
        out.append(CellSpec(cell_id=cell_id, profile=profile, workload=workload))
    return out


def _matches_any(profile: Mapping[str, Any], rules: list[Mapping[str, Any]]) -> bool:
    return any(all(profile.get(k) == v for k, v in rule.items()) for rule in rules)


@dataclass
class MatrixPlan:
    name: str
    cells: list[CellSpec] = field(default_factory=list)


def plan_from_file(matrix_path: Path) -> MatrixPlan:
    """Load and expand a matrix from a YAML file.

    PyYAML is required at runtime; if unavailable, fall back to a JSON loader
    so the smoke matrix can still be expressed as JSON for environments where
    pyyaml isn't pre-installed (CI containers, minimal dev hosts).
    """
    text = Path(matrix_path).read_text()
    doc: Mapping[str, Any]
    if matrix_path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "PyYAML required for .yaml matrix files; install pyyaml or use a .json matrix file"
            ) from e
        doc = yaml.safe_load(text) or {}
    else:
        doc = json.loads(text)
    name = str(doc.get("name") or matrix_path.stem)
    return MatrixPlan(name=name, cells=expand({**doc, "name": name}))


# ---------------------------------------------------------------------------
# Share-dir refusal: matrices that drive a 9p host_share need a workspace
# that actually contains the lua-lsm-tools and kernel sources, otherwise the
# guest workloads will fail with confusing "no such file" errors after SSH up.


class ShareDirError(ValueError):
    pass


REQUIRED_SHARE_ENTRIES = ("lua-lsm-tools", "kernel/linux")
# Workloads whose every fixture lives inside this repository's checkout;
# derived from workloads.SPECS so the share-entry requirement can never
# drift from the workload registration table.
SELF_CONTAINED_WORKLOADS = frozenset(
    spec.name for spec in workloads.SPECS.values() if spec.self_contained
)


def required_share_entries(workload_names: list[str]) -> tuple[str, ...]:
    """Return the share entries needed by a set of workload names."""
    if workload_names and all(name in SELF_CONTAINED_WORKLOADS for name in workload_names):
        return ("lua-lsm-testsuite",)
    return REQUIRED_SHARE_ENTRIES


def assert_share_dir(share_dir: Path, required_entries: tuple[str, ...] | None = None) -> None:
    """Refuse a workspace that's missing the load-bearing trees.

    The matrix runner calls this once at planning time so a bad SHARE_DIR
    fails before any QEMU is spawned.
    """
    sd = Path(share_dir)
    if not sd.exists() or not sd.is_dir():
        raise ShareDirError(f"share_dir does not exist or is not a directory: {sd}")
    entries = REQUIRED_SHARE_ENTRIES if required_entries is None else required_entries
    missing = [name for name in entries if not (sd / name).exists()]
    if missing:
        raise ShareDirError(
            f"share_dir {sd} is missing required entries: {missing}; "
            f"expected a workspace containing {entries}."
        )


# ---------------------------------------------------------------------------
# Port allocator: every cell needs a distinct localhost forward port for the
# guest's sshd. We allocate sequentially from a base; the runner records the
# allocation so duplicates from a stale config get rejected at plan time.

DEFAULT_PORT_BASE = 10023


def allocate_ports(n: int, base: int = DEFAULT_PORT_BASE) -> list[int]:
    """Return n distinct ports starting at base.

    Pure function; the runner is responsible for refusing if any port is
    already bound on the host. We keep this separate from binding so unit
    tests can drive the planner without touching real sockets.
    """
    if n < 0:
        raise ValueError(f"n must be non-negative, got {n}")
    if base <= 0 or base + n > 65536:
        raise ValueError(f"port range [{base}, {base + n}) out of bounds")
    return [base + i for i in range(n)]


# ---------------------------------------------------------------------------


@dataclass
class ExecutorOpts:
    parallel: int = 1
    runs_root: Path = field(default_factory=lambda: Path("runs"))
    matrix_path: Path | None = None
    port_base: int = DEFAULT_PORT_BASE
    share_dir: Path | None = None
    # When set, the executor passes this registry to each cell runner via
    # the callback so SIGINT can reap any active QEMU child within
    # SHUTDOWN_GRACE. Callers that need SIGINT-driven reap construct one and
    # let _build_cell_runner_callback wire it into CellInputs.
    registry: run_registry.RunRegistry | None = None


def _cell_artifact_dir(runs_dir: Path, cell: CellSpec) -> Path:
    return runs_dir / cell.cell_id


def _aborted_result(cell_id: str, reason: str) -> dict[str, Any]:
    """Synthetic result.json for a cell that never got to run."""
    result = schemas.empty_result(cell_id)
    result["verdict"] = "aborted"
    result["reason"] = reason
    result["finished_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    return result


def _execute_cells(
    plan: MatrixPlan,
    opts: ExecutorOpts,
    cell_runner_fn,
    runs_dir: Path,
) -> dict[str, dict[str, Any]]:
    """Run every cell with bounded parallelism; own the SIGINT machinery.

    Returns `finished`, the {cell_id: result} map the caller uses to build
    matrix.json's cells section -- cells absent from it never reported a
    result and are recorded as `aborted` by the caller.

    A SIGINT during execution stops scheduling further cells and cancels any
    queued future; the handler block below is the subtlest code in the repo
    and is moved here VERBATIM from run_matrix (tests MatrixSigintCancel /
    SigintReap pin its behavior). matrix.json is still written by the caller
    so a partial run is triageable.
    """
    ports = allocate_ports(len(plan.cells), base=opts.port_base)

    # Track unfinished cells so the SIGINT path can record `aborted` for them
    # without racing against the worker's own write.
    cells_lock = threading.Lock()
    finished: dict[str, dict[str, Any]] = {}
    aborted_event = threading.Event()

    def _run_one(cell: CellSpec, port: int) -> dict[str, Any]:
        if aborted_event.is_set():
            return _aborted_result(cell.cell_id, "interrupted before launch")
        art = _cell_artifact_dir(runs_dir, cell)
        art.mkdir(parents=True, exist_ok=True)
        result = cell_runner_fn(cell, art, port)
        with cells_lock:
            finished[cell.cell_id] = result
        return result

    workers = max(1, int(opts.parallel))
    results: list[dict[str, Any]] = []
    prev_handler = None
    # Shared between the SIGINT handler and the parallel branch: holds the
    # {future: cell} map so the handler can cancel any not-yet-started future
    # rather than wait for cf.as_completed to drain the queued submissions.
    futs_holder: dict[cf.Future, CellSpec] = {}

    def _on_sigint(signum, frame):
        aborted_event.set()
        # Reap any active QEMU children registered by per-cell runners so a
        # wedged workload doesn't keep the host VM alive after the matrix
        # gives up. Best-effort: registry.stop_all swallows per-handle
        # exceptions and returns the list it attempted to reap.
        if opts.registry is not None:
            with contextlib.suppress(Exception):
                opts.registry.stop_all(timeout_s=run_registry.SHUTDOWN_GRACE_S)
        # Cancel any queued (not-yet-started) future. cf.as_completed otherwise
        # blocks until the threadpool gets around to running each submission,
        # which negates the abort for back-of-queue cells. The as_completed
        # loop translates CancelledError into an aborted result; the post-loop
        # pass writes that result to disk for cells whose artifact dir doesn't
        # yet exist.
        with cells_lock:
            futs_snapshot = list(futs_holder.keys())
        for fut in futs_snapshot:
            if not fut.done():
                fut.cancel()
        # Do not re-raise; let the loop drain so partial matrix.json is
        # still written. A second SIGINT will take the default action.
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    try:
        prev_handler = signal.signal(signal.SIGINT, _on_sigint)
        if workers == 1:
            for cell, port in zip(plan.cells, ports):
                if aborted_event.is_set():
                    break
                results.append(_run_one(cell, port))
        else:
            with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                with cells_lock:
                    futs_holder.update(
                        {
                            ex.submit(_run_one, cell, port): cell
                            for cell, port in zip(plan.cells, ports)
                        }
                    )
                for fut in cf.as_completed(list(futs_holder)):
                    try:
                        results.append(fut.result())
                    except cf.CancelledError:
                        cell = futs_holder[fut]
                        results.append(
                            _aborted_result(cell.cell_id, "cancelled by SIGINT before launch")
                        )
                    except Exception as e:
                        cell = futs_holder[fut]
                        results.append(
                            _aborted_result(cell.cell_id, f"worker raised {type(e).__name__}: {e}")
                        )
    finally:
        if prev_handler is not None:
            signal.signal(signal.SIGINT, prev_handler)

    return finished


def run_matrix(plan: MatrixPlan, opts: ExecutorOpts, cell_runner_fn) -> dict[str, Any]:
    """Execute every cell with bounded parallelism and write matrix.json.

    `cell_runner_fn(cell: CellSpec, artifact_dir: Path, port: int) -> dict`
    returns the per-cell result.json dict. The matrix executor is unaware of
    how the cell runs (real QEMU, mocked subprocess, dry-run): it sees only
    the result dict and aggregates totals.
    """
    if opts.share_dir is not None:
        assert_share_dir(
            opts.share_dir,
            required_share_entries([cell.workload for cell in plan.cells]),
        )

    matrix = schemas.empty_matrix()
    matrix["started_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    matrix["config"] = {
        "parallel": opts.parallel,
        "matrix_path": str(opts.matrix_path) if opts.matrix_path else None,
        "port_base": opts.port_base,
        "share_dir": str(opts.share_dir) if opts.share_dir else None,
    }
    runs_dir = opts.runs_root / _utc_now_id()
    runs_dir.mkdir(parents=True, exist_ok=True)

    finished = _execute_cells(plan, opts, cell_runner_fn, runs_dir)

    # Build the cells list from the planned set (so cells the runner never
    # got to land in matrix.json as `aborted`).
    cells_section: list[dict[str, Any]] = []
    for cell in plan.cells:
        result = finished.get(cell.cell_id)
        if result is None:
            result = _aborted_result(cell.cell_id, "interrupted before completion")
            (_cell_artifact_dir(runs_dir, cell)).mkdir(parents=True, exist_ok=True)
            (_cell_artifact_dir(runs_dir, cell) / "result.json").write_text(
                json.dumps(result, indent=2, sort_keys=True)
            )
        cells_section.append(
            {
                "cell_id": cell.cell_id,
                "verdict": result.get("verdict"),
                "started_at": result.get("started_at"),
                "finished_at": result.get("finished_at"),
                "artifact_dir": str(_cell_artifact_dir(runs_dir, cell)),
            }
        )
    matrix["cells"] = cells_section
    matrix["totals"] = schemas.aggregate_totals(matrix["cells"])
    matrix["finished_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    (runs_dir / "matrix.json").write_text(json.dumps(matrix, indent=2, sort_keys=True))
    return matrix
