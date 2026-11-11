"""Single-cell orchestrator: one boot of one VM running one workload.

A cell is the unit of test isolation: a fresh debug-kernel QEMU, a freshly
mounted rootfs, a single workload, then teardown. The cell runner ties
together cmdline composition, QEMU spawn, SSH-up, perf-stats snapshotting,
workload execution, dmesg capture, classifier, and result.json emission.

Workloads are pluggable: callers pass a callable that takes (target, ctx)
and returns a `WorkloadResult`. Concrete workloads (smoke, bench, unixbench,
verify-cleanup, lkdtm) live in harness.workloads.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import shlex
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import (
    bundle,
    classifier,
    classifier_patterns,
    lkdtm_cell,
    perf_snapshot,
    preflight,
    qemu,
    run_registry,
    schemas,
    signature,
    ssh,
    workloads,
)
from .celltypes import CellContext, WorkloadFn, WorkloadResult
from .hostenv import HostEnv, cell_kvm_check, detect
from .kernel_cmdline import compose_env
from .timeutil import now_iso

__all__ = [
    "CellContext",
    "CellInputs",
    "WorkloadFn",
    "WorkloadResult",
    "derive_guest_relpath",
    "run_cell",
]

# Remote paths in the guest where the kernel exposes lua-lsm telemetry.
GUEST_STATS = "/sys/kernel/security/lua/stats"
GUEST_LSM_FUNCS = "/sys/kernel/security/lua/lsm_funcs"
GUEST_DMESG_CMD = "dmesg --kernel --color=never --decode"
GUEST_JOURNAL_CMD = "journalctl --no-pager -k -o short-precise || true"
GUEST_HOST_SHARE = "/mnt/host"


@dataclass
class CellInputs:
    cell_id: str
    profile: Mapping[str, Any]
    workload_fn: WorkloadFn
    workload_name: str
    launcher: Path
    artifact_dir: Path
    ssh_target: ssh.SshTarget
    base_env: Mapping[str, str] = field(default_factory=dict)
    boot_timeout_s: float = 180.0
    workload_timeout_s: float = 600.0
    kvm_required: bool = True
    # Path under WORKSPACE that this cell's artifact_dir maps to inside the
    # guest's /mnt/host. Set by the matrix runner / CLI; left empty means the
    # dmesg --follow start step is skipped (useful for unit tests with no
    # real share mount).
    guest_artifact_relpath: str | None = None
    # Workspace path used to derive the guest_artifact_relpath; if absent,
    # the runner does not start a guest-side dmesg follower.
    workspace_root: Path | None = None
    # When True, the launcher inherits stdio (foreground console). result.json
    # is still written at teardown.
    interactive: bool = False
    # Bundle store shared across cells in a matrix run; used to dedup splat
    # bundles by signature_sha1. None means "do not write bundles for this
    # cell" (e.g. unit tests, image-warm).
    bundle_store: bundle.BundleStore | None = None
    # Per-run registry of active QEMU handles; the matrix executor's SIGINT
    # handler reaps these. None means "no registry" (single-cell run with no
    # SIGINT-driven reap requirement).
    run_registry: run_registry.RunRegistry | None = None
    # Bundle source bookkeeping; only populated when the matrix knows about
    # the host's kernel tree / config / rootfs paths.
    kernel_tree: Path | None = None
    kernel_config_path: Path | None = None
    kernel_config_baseline: Path | None = None
    rootfs_image: Path | None = None
    decode_script: Path | None = None
    policy_paths: tuple[Path, ...] = field(default_factory=tuple)
    # Override path for the rootfs warm-marker; when None and rootfs_image is
    # set, the runner derives `<rootfs_image>.warm-marker` to match the
    # convention used by the `image-warm` CLI helper.
    warm_marker: Path | None = None


def _make_cell_id(profile: Mapping[str, Any], workload_name: str) -> str:
    """Stable, short cell id: <UTC-timestamp>_<short-hash>.

    The hash is a stable function of the profile + workload so re-runs of the
    same cell on the same UTC second produce identical-looking ids only when
    they're truly identical inputs.
    """
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = json.dumps({"profile": dict(profile), "workload": workload_name}, sort_keys=True)
    h = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:8]
    return f"{ts}_{h}"


def _now_iso() -> str:
    # Kept as a thin alias: call sites predate harness.timeutil.
    return now_iso()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _maybe_snapshot(target: ssh.SshTarget) -> perf_snapshot.Snapshot | None:
    stats_text, funcs_text = _fetch_perf_texts(target)
    if stats_text is None and funcs_text is None:
        return None
    snap = perf_snapshot.Snapshot()
    if stats_text is not None:
        snap.counters = perf_snapshot.parse_stats_text(stats_text)
    if funcs_text is not None:
        snap.lsm_funcs = perf_snapshot.parse_lsm_funcs_text(funcs_text)
    return snap


def _perf_snapshot_strict(
    target: ssh.SshTarget,
) -> tuple[perf_snapshot.Snapshot | None, str | None]:
    """Perf-cell snapshot: BOTH stats and lsm_funcs are required AND must
    parse to a structurally complete `Snapshot`.

    A structurally complete snapshot contains every key in
    `schemas.REQUIRED_COUNTER_KEYS` and at least one parsed lsm_funcs row.
    Either side missing or malformed yields (None, reason) so the caller can
    surface skip:stats-unavailable rather than silently producing partial
    deltas.
    """
    stats_text, funcs_text = _fetch_perf_texts(target)
    missing: list[str] = []
    if stats_text is None:
        missing.append(GUEST_STATS)
    if funcs_text is None:
        missing.append(GUEST_LSM_FUNCS)
    if missing:
        return None, "missing perf telemetry: " + ", ".join(missing)
    snap = perf_snapshot.Snapshot()
    snap.counters = perf_snapshot.parse_stats_text(stats_text or "")
    snap.lsm_funcs = perf_snapshot.parse_lsm_funcs_text(funcs_text or "")
    invalid = perf_snapshot.validate_snapshot(snap)
    if invalid is not None:
        return None, "malformed perf telemetry: " + invalid
    return snap, None


def _fetch_perf_texts(target: ssh.SshTarget) -> tuple[str | None, str | None]:
    """Fetch stats and lsm_funcs separately so callers can apply strict perf
    semantics (both required for kind==perf cells)."""
    stats_text = ssh.fetch_text(target, GUEST_STATS)
    funcs_text = ssh.fetch_text(target, GUEST_LSM_FUNCS)
    return stats_text, funcs_text


# Guest fixtures whose presence the cell runner verifies before invoking a
# workload live in workloads.SPECS (the workload registration table), next
# to the workload function itself.


def _check_workload_fixture(
    target: ssh.SshTarget, workload_name: str, policy_path: str | None = None
) -> Mapping[str, str] | None:
    """Verify the workload's host_share fixtures are readable in the guest.

    Returns a SKIP payload when a fixture is missing, None when all are
    present (or the workload has no fixture requirements).
    """
    spec = workloads.SPECS.get(workload_name)
    paths = list(spec.guest_fixtures) if spec is not None else []
    if workload_name == "smoke" and policy_path:
        # Smoke registers a specific policy file; require its presence
        # explicitly so a typo'd --policy fails fast as fixture-missing.
        paths.append(policy_path)
    if not paths:
        return None
    # The preflight helper expects -x; for .lua files we want -r instead.
    for p in paths:
        flag = "-x" if p.endswith(".sh") else "-r"
        r = ssh.run(target, f"test {flag} {p}", timeout_s=10.0)
        if r.returncode != 0:
            return {
                "verdict": "skip:fixture-missing",
                "reason": f"required workload fixture missing or unreadable: {p}",
                "remediation": (
                    f"ensure the host_share workspace contains a built copy of "
                    f"{p}; run the workload's build/install step on the host first."
                ),
            }
    return None


def derive_guest_relpath(
    artifact_dir: Path, workspace_root: Path | None, override: str | None
) -> str | None:
    if override is not None:
        return override
    if workspace_root is None:
        return None
    try:
        rel = Path(artifact_dir).resolve().relative_to(Path(workspace_root).resolve())
    except ValueError:
        return None
    return str(rel)


def _start_dmesg_follower(target: ssh.SshTarget, guest_rel: str) -> None:
    """Start `dmesg --follow > /mnt/host/<rel>/dmesg.log` in the guest.

    Best-effort: if dmesg or the share isn't reachable the workload will
    surface its own failure later. We `setsid` so the follower survives
    after this SSH session closes; the teardown stops it explicitly.
    """
    rel = guest_rel.strip("/")
    target_path = f"{GUEST_HOST_SHARE}/{rel}/dmesg.log"
    cmd = (
        f"set -eu; "
        f"mkdir -p {shlex.quote(f'{GUEST_HOST_SHARE}/{rel}')}; "
        f"setsid -f sh -c "
        f"{shlex.quote(f'exec dmesg --follow --color=never > {target_path} 2>&1')} "
        f"</dev/null >/dev/null 2>&1 || true"
    )
    ssh.run(target, cmd, timeout_s=15.0)


def _stop_dmesg_follower(target: ssh.SshTarget) -> None:
    ssh.run(target, "pkill -TERM -f 'dmesg --follow' || true", timeout_s=10.0)


def _write_cell_record(art: Path, cell_id: str, inputs: CellInputs) -> None:
    """Write cell.json with the cell's *intent* before any boot attempt.

    cell.json is written distinct from result.json: result.json carries the
    eventual verdict, but cell.json is the durable record of "what was this
    cell going to do" -- profile, workload, ssh target, kernel/rootfs paths.
    Useful when the cell crashes before result.json is finalised.
    """
    record = {
        "schema_version": schemas.SCHEMA_VERSION,
        "cell_id": cell_id,
        "profile": dict(inputs.profile),
        "workload": inputs.workload_name,
        "kernel_image": str(inputs.base_env.get("KERNEL_IMG", "")) or None,
        "rootfs_image": str(inputs.base_env.get("ROOTFS_IMG", "")) or None,
        "host_ssh_port": inputs.ssh_target.port,
        "share_dir": str(inputs.base_env.get("SHARE_DIR", "")) or None,
        "boot_timeout_s": inputs.boot_timeout_s,
        "workload_timeout_s": inputs.workload_timeout_s,
        "launcher": str(inputs.launcher),
        "artifact_dir": str(art),
    }
    _write_text(art / "cell.json", json.dumps(record, indent=2, sort_keys=True))


def run_cell(inputs: CellInputs, host: HostEnv | None = None) -> dict[str, Any]:
    """Run one cell end-to-end and return the populated result.json dict.

    On success the cell's artifact_dir contains: cell.json, serial.log,
    dmesg.log, journalctl-kb.txt, stats-before.txt, stats-after.txt,
    lsm_funcs-before.txt, lsm_funcs-after.txt, qemu-cmdline.txt,
    extra-cmdline.txt, result.json.

    Structure: init result -> planning-time gates (KVM, cmdline composition,
    perf warm marker) -> spawn -> boot/preflight gates -> workload ->
    snapshots -> teardown capture -> classify. Every gate's early return
    goes through _finish_early so a gate refusal always leaves a valid,
    written result.json.
    """
    host = host if host is not None else detect()
    cell_id = inputs.cell_id or _make_cell_id(inputs.profile, inputs.workload_name)
    art = inputs.artifact_dir
    art.mkdir(parents=True, exist_ok=True)

    # cell.json captures "what was this cell going to do" before any spawn.
    _write_cell_record(art, cell_id, inputs)

    result = schemas.empty_result(cell_id)
    result["started_at"] = _now_iso()
    result["workload"] = inputs.workload_name
    result["host"] = {"system": host.system, "release": host.release, "has_kvm": host.has_kvm}

    profile = dict(inputs.profile)
    result["kconfig_profile"] = profile.get("kconfig_profile")

    # Early SKIP: KVM required but host has none. Don't spend time spawning
    # something we know will fail / be misleading.
    skip = cell_kvm_check(host, kvm_required=inputs.kvm_required)
    if skip is not None:
        result["verdict"] = skip["verdict"]
        result["reason"] = skip["reason"]
        return _finish_early(result, art)

    # Build EXTRA_CMDLINE and the launch env.
    try:
        env = compose_env(profile, inputs.base_env)
    except Exception as e:
        result["verdict"] = "harness-error"
        result["reason"] = f"cmdline composition failed: {e}"
        return _finish_early(result, art)
    result["cmdline"] = env["EXTRA_CMDLINE"]
    _write_text(art / "extra-cmdline.txt", env["EXTRA_CMDLINE"] + "\n")
    _write_text(art / "qemu-cmdline.txt", qemu.render_launch_command(inputs.launcher, env) + "\n")

    ctx = CellContext(cell_id=cell_id, artifact_dir=art, target=inputs.ssh_target, profile=profile)
    workload_returncode: int | None = None

    # Perf cells require a warm rootfs (cold-boot dwarfs the measurement).
    # Gate BEFORE qemu.spawn so the runner does not pay boot time for a cell
    # that's going to be discarded as skip:image-not-warm anyway.
    warm_skip = _perf_warm_skip(inputs, profile)
    if warm_skip is not None:
        result["verdict"] = str(warm_skip["verdict"])
        result["reason"] = str(warm_skip["reason"])
        return _finish_early(result, art, ctx)

    handle: qemu.QemuHandle | None = None
    registered = False
    try:
        try:
            handle = qemu.spawn(
                inputs.launcher,
                env,
                art / "serial.log",
                interactive=inputs.interactive,
            )
        except qemu.QemuLaunchError as e:
            result["verdict"] = "harness-error"
            result["reason"] = f"qemu launch failed: {e}"
            return _classify_and_finalize(result, art, inputs, ctx, workload_returncode)
        if inputs.run_registry is not None:
            inputs.run_registry.register(cell_id, handle)
            registered = True
        result["qemu_pid"] = handle.proc.pid
        result["kernel_image"] = env.get("KERNEL_IMG")
        result["rootfs_image"] = env.get("ROOTFS_IMG")

        if not ssh.wait_for_ssh(inputs.ssh_target, timeout_s=inputs.boot_timeout_s):
            result["verdict"] = "boot-timeout"
            result["reason"] = f"ssh did not come up within {inputs.boot_timeout_s:.0f}s"
            return _classify_and_finalize(result, art, inputs, ctx, workload_returncode)

        # Refuse the cell if the host_share wasn't mounted -- the workload
        # would otherwise fail with a confusing "no such file" error.
        share_skip = preflight.host_share_check(inputs.ssh_target)
        if share_skip is not None:
            result["verdict"] = str(share_skip["verdict"])
            result["reason"] = str(share_skip["reason"])
            return _classify_and_finalize(result, art, inputs, ctx, workload_returncode)

        # Refuse the cell if the workload's required guest-side fixture is
        # missing -- the smoke policy file, bench.lua, the verify-cleanup
        # script, etc. Surfaces as skip:fixture-missing so a typo'd workspace
        # doesn't masquerade as a real workload failure.
        policy_guest_path: str | None = None
        if profile.get("policy"):
            policy_guest_path = workloads.policy_guest_path(
                inputs.workload_name, str(profile["policy"])
            )
        fixture_skip = _check_workload_fixture(
            inputs.ssh_target,
            inputs.workload_name,
            policy_path=policy_guest_path,
        )
        if fixture_skip is not None:
            result["verdict"] = str(fixture_skip["verdict"])
            result["reason"] = str(fixture_skip["reason"])
            return _classify_and_finalize(result, art, inputs, ctx, workload_returncode)

        # Start the in-guest dmesg follower so we capture the splat as it's
        # printed, not just whatever survived to teardown. Skip when we
        # have no relpath to write into (unit tests, image-warm).
        guest_rel = derive_guest_relpath(art, inputs.workspace_root, inputs.guest_artifact_relpath)
        follower_started = False
        if guest_rel is not None:
            _start_dmesg_follower(inputs.ssh_target, guest_rel)
            follower_started = True

        # Snapshot BEFORE the workload. Perf cells require BOTH stats and
        # lsm_funcs (the deltas are not meaningful when one half is absent);
        # other kinds tolerate a partial or absent snapshot.
        if profile.get("kind") == "perf":
            before, perf_skip_reason = _perf_snapshot_strict(inputs.ssh_target)
            if before is None:
                payload = perf_snapshot.stats_available_skip_payload(
                    reason=perf_skip_reason or "perf telemetry unavailable",
                )
                result["verdict"] = payload["verdict"]
                result["reason"] = str(payload["reason"])
                # Leave result["perf"] absent so consumers can distinguish a
                # skipped perf cell from one with measured deltas.
                if follower_started:
                    _stop_dmesg_follower(inputs.ssh_target)
                return _classify_and_finalize(result, art, inputs, ctx, workload_returncode)
        else:
            before = _maybe_snapshot(inputs.ssh_target)
        if before is not None:
            _persist_snapshot(art, "before", before)

        try:
            wl_result = inputs.workload_fn(inputs.ssh_target, ctx)
            workload_returncode = wl_result.returncode
        except Exception as e:
            result["verdict"] = "harness-error"
            result["reason"] = f"workload raised {type(e).__name__}: {e}"
            if follower_started:
                _stop_dmesg_follower(inputs.ssh_target)
            return _classify_and_finalize(result, art, inputs, ctx, workload_returncode)
        result["reason"] = wl_result.notes or None

        # Snapshot AFTER, compute deltas. Perf cells require the after-snapshot
        # to be structurally complete too -- otherwise we'd emit a "pass" with
        # partial deltas built from a malformed half. Other kinds tolerate a
        # partial or absent after-snapshot.
        perf_after_skip: tuple[str, str] | None = None
        if profile.get("kind") == "perf":
            after, after_skip_reason = _perf_snapshot_strict(inputs.ssh_target)
            if after is None:
                perf_after_skip = (
                    "skip:stats-unavailable",
                    after_skip_reason or "perf telemetry unavailable after workload",
                )
        else:
            after = _maybe_snapshot(inputs.ssh_target)
        if before is not None and after is not None and perf_after_skip is None:
            _persist_snapshot(art, "after", after)
            result["perf"] = {
                "snapshots": {"before": before.to_dict(), "after": after.to_dict()},
                "deltas": perf_snapshot.diff(before, after),
            }

        _teardown_logs(inputs, art, follower_started)

        return _classify_and_finalize(
            result,
            art,
            inputs,
            ctx,
            workload_returncode,
            perf_after_skip=perf_after_skip,
        )
    finally:
        if registered and inputs.run_registry is not None:
            inputs.run_registry.unregister(cell_id)
        if handle is not None:
            qemu.stop(handle)


def _finish_early(
    result: dict[str, Any], art: Path, ctx: CellContext | None = None
) -> dict[str, Any]:
    """Stamp finished_at (+ commands when a ctx exists) and write result.json.

    The shared tail of every planning-time gate refusal in run_cell.
    """
    result["finished_at"] = _now_iso()
    if ctx is not None:
        result["commands"] = list(ctx.commands)
    _write_result(art, result)
    return result


def _perf_warm_skip(inputs: CellInputs, profile: Mapping[str, Any]) -> Mapping[str, str] | None:
    """Warm-marker gate for perf cells; None means the cell may proceed."""
    if profile.get("kind") != "perf" or inputs.rootfs_image is None:
        return None
    marker = inputs.warm_marker
    if marker is None:
        marker = preflight.default_warm_marker(Path(inputs.rootfs_image))
    return preflight.image_warm_check(inputs.rootfs_image, marker)


def _teardown_logs(inputs: CellInputs, art: Path, follower_started: bool) -> None:
    """Capture the kernel's log channels at teardown.

    With the dmesg follower running, stopping it and letting the 9p mount
    flush is enough. Without one (unit tests, short-circuited cells), dmesg
    is captured one-shot instead. journalctl is captured either way -- it is
    the tertiary audit trail and never influences the verdict.
    """
    if follower_started:
        _stop_dmesg_follower(inputs.ssh_target)
        # Give the kernel a moment to flush the last lines through 9p.
        time.sleep(0.5)
    else:
        # No follower: capture dmesg one-shot at teardown.
        dmesg_text = _capture(inputs.ssh_target, GUEST_DMESG_CMD, timeout=60.0)
        if dmesg_text is not None:
            (art / "dmesg.log").write_text(dmesg_text)

    journal_text = _capture(inputs.ssh_target, GUEST_JOURNAL_CMD, timeout=60.0)
    if journal_text is not None:
        (art / "journalctl-kb.txt").write_text(journal_text)


def _capture(target: ssh.SshTarget, cmd: str, timeout: float) -> str | None:
    r = ssh.run(target, cmd, timeout_s=timeout)
    if r.returncode != 0 and not r.stdout:
        return None
    return r.stdout


def _persist_snapshot(art: Path, label: str, snap: perf_snapshot.Snapshot) -> None:
    """Write the parseable forms back as text so a developer can re-read them."""
    counters_text = "\n".join(f"{k}\t=\t{v}" for k, v in sorted(snap.counters.items())) + "\n"
    _write_text(art / f"stats-{label}.txt", counters_text)
    funcs_text = "stats for lua-lsm (ns)\n"
    funcs_text += (
        "num name                         nlsm        "
        "count           total    average      maxtime\n"
    )
    funcs_text += "----\n"
    for i, (name, row) in enumerate(sorted(snap.lsm_funcs.items()), start=1):
        funcs_text += (
            f"{i:>3} {name:<24} {row.get('nlsm', 0):>8} "
            f"{row.get('count', 0):>12} {row.get('total', 0):>15} "
            f"{row.get('average', 0):>10} {row.get('maxtime', 0):>12}\n"
        )
    _write_text(art / f"lsm_funcs-{label}.txt", funcs_text)


def _classify_and_finalize(
    result: dict[str, Any],
    art: Path,
    inputs: CellInputs,
    ctx: CellContext,
    workload_returncode: int | None,
    perf_after_skip: tuple[str, str] | None = None,
) -> dict[str, Any]:
    serial_log = art / "serial.log"
    dmesg_log = art / "dmesg.log"
    serial_has_text = serial_log.exists() and serial_log.stat().st_size > 0
    dmesg_has_text = dmesg_log.exists() and dmesg_log.stat().st_size > 0

    # LKDTM rc=77 must short-circuit before the no-dmesg early return: a
    # kernel built without CONFIG_LKDTM=y produces zero log bytes (the
    # provoke-crash node was never written to), and we want the SKIP verdict
    # rather than the no-dmesg failure verdict.
    if (
        inputs.workload_name == "lkdtm"
        and workload_returncode == lkdtm_cell.LKDTM_PROVOKE_RC
        and result["verdict"] is None
    ):
        result["verdict"] = "skip:no-lkdtm"
        result["reason"] = "LKDTM provoke-crash node missing (CONFIG_LKDTM=n)"
        result["finished_at"] = _now_iso()
        result["commands"] = list(ctx.commands)
        _write_result(art, result)
        return result

    if not serial_has_text and not dmesg_has_text:
        if result["verdict"] is None:
            result["verdict"] = "no-dmesg"
            result["reason"] = "no serial.log or dmesg.log content captured"
        result["finished_at"] = _now_iso()
        result["commands"] = list(ctx.commands)
        _write_result(art, result)
        return result

    paths = [p for p in (serial_log, dmesg_log) if p.exists() and p.stat().st_size > 0]
    hits = classifier.classify_files(paths)
    result["classifier_pattern_version"] = classifier_patterns.PATTERN_VERSION
    result["classifier_hits"] = [h.__dict__ if hasattr(h, "__dict__") else h for h in hits]

    # Tertiary audit-trail parse: classify the in-guest journalctl capture
    # with the same pattern set so a triage script can spot splat headers
    # that only surfaced after the in-guest dmesg buffer rolled. Never
    # influences verdict -- that contract belongs to serial+dmesg.
    journal_log = art / "journalctl-kb.txt"
    if journal_log.exists() and journal_log.stat().st_size > 0:
        journal_hits = classifier.classify_files([journal_log])
        result["journalctl_hits"] = [
            h.__dict__ if hasattr(h, "__dict__") else h for h in journal_hits
        ]

    if result["verdict"] is None:
        if hits:
            result["verdict"] = "kernel-bug"
        elif (
            workload_returncode is not None
            and workload_returncode != 0
            and inputs.workload_name != "lkdtm"
        ):
            # The workload returned non-zero but the kernel produced no
            # classifier hit -- a guest-side failure we surface as
            # workload-fail (distinct from kernel-bug).
            result["verdict"] = "workload-fail"
            if not result.get("reason"):
                result["reason"] = f"workload returned non-zero exit code: {workload_returncode}"
        elif perf_after_skip is not None:
            # Perf cell ran to completion with no kernel/workload failure but
            # the after-snapshot was missing/malformed. Surface as
            # skip:stats-unavailable instead of pass-with-partial-deltas so
            # bisect and perf-regression tooling don't trust a misleading
            # measurement.
            result["verdict"] = perf_after_skip[0]
            result["reason"] = perf_after_skip[1]
            result["perf"] = {"snapshots": None, "deltas": None}
        else:
            result["verdict"] = "pass"

    # LKDTM positive control: invert the verdict when this cell is the LKDTM
    # cell. The lkdtm_cell helper handles the rc=77 SKIP fallback too.
    if inputs.workload_name == "lkdtm":
        result = lkdtm_cell.adjust_verdict_for_lkdtm(result, workload_returncode)

    # commands.sh in the bundle is populated from result["commands"], so the
    # field MUST be written before _emit_bundle runs. Writing it here also
    # means a developer reading result.json sees the same ordered replay log
    # whether the cell produced a bundle or not.
    result["commands"] = list(ctx.commands)

    # Bisect bundle: emit when the classifier saw a real splat AND the caller
    # wired a BundleStore. Skipping when bundle_store is None keeps unit tests
    # and ad-hoc single-cell runs lean.
    if hits and inputs.bundle_store is not None:
        try:
            bundle_meta = _emit_bundle(result, art, inputs)
            if bundle_meta is not None:
                result["bundle_dir"] = bundle_meta["bundle_dir"]
                result["signature_sha1"] = bundle_meta["signature_sha1"]
                result["signature_kind"] = bundle_meta["signature_kind"]
        except Exception as e:
            result["bundle_error"] = f"{type(e).__name__}: {e}"

    result["finished_at"] = _now_iso()
    _write_result(art, result)
    return result


def _splat_slice_from_logs(art: Path, window: int = 50) -> list[str]:
    """Return up to `window` log lines centered on the first classifier hit.

    Classifies each log channel (serial.log, dmesg.log) independently using
    per-channel local line numbers, then picks the channel that contains the
    earliest hit and centers the window on that hit's line in that channel.
    This guarantees the returned slice contains the hit's substring even when
    one channel is non-empty but clean and the splat lives only in the other.
    """
    serial_log = art / "serial.log"
    dmesg_log = art / "dmesg.log"
    channels = [serial_log, dmesg_log]
    per_channel = classifier.classify_files_per_channel(channels)

    chosen_path: Path | None = None
    chosen_line: int | None = None
    for path in channels:
        chits = per_channel.get(path) or []
        if not chits:
            continue
        first = next(
            (h for h in chits if isinstance(getattr(h, "line", None), int) and h.line >= 1),
            None,
        )
        if first is None:
            continue
        if chosen_line is None or first.line < chosen_line:
            chosen_path = path
            chosen_line = first.line

    if chosen_path is None:
        # No classifier hit in either channel; fall back to the first window
        # of whichever channel has content, preferring serial.
        for path in channels:
            if path.exists() and path.stat().st_size > 0:
                try:
                    return path.read_text(errors="replace").splitlines()[:window]
                except OSError:
                    return []
        return []

    try:
        lines = chosen_path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    if not lines:
        return []
    half = window // 2
    start = max(0, (chosen_line - 1) - half)
    end = min(len(lines), start + window)
    start = max(0, end - window)
    return lines[start:end]


def _emit_bundle(result: dict[str, Any], art: Path, inputs: CellInputs) -> dict[str, str] | None:
    """Build a signature, write a bundle, and return metadata for result.json."""
    splat_slice = _splat_slice_from_logs(art, window=50)
    if not splat_slice:
        return None
    sig = signature.build_signature(splat_slice)
    sources = bundle.BundleSources(
        cell_id=result["cell_id"],
        artifact_dir=art,
        cmdline=str(result.get("cmdline") or ""),
        kernel_tree=inputs.kernel_tree,
        kernel_config_path=inputs.kernel_config_path,
        kernel_config_baseline=inputs.kernel_config_baseline,
        rootfs_image=inputs.rootfs_image,
        policies=tuple(inputs.policy_paths),
        commands=tuple(result.get("commands") or []),
        decode_script=inputs.decode_script,
        splat_slice=tuple(splat_slice),
    )
    bundle_dir = bundle.write_bundle(
        inputs.bundle_store,
        sources,
        sig.sha1,
        sig.kind,
    )
    return {
        "bundle_dir": str(bundle_dir),
        "signature_sha1": sig.sha1,
        "signature_kind": sig.kind,
    }


def _write_result(art: Path, result: dict[str, Any]) -> None:
    (art / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True))
