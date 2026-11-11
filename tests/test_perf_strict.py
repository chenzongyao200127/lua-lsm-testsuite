"""Unit tests for perf-cell strict preflight (harness.cell_runner).

Moved from tests/test_round2.py: perf cells skip on a cold rootfs and
require structurally complete stats AND lsm_funcs.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from harness import cell_runner, preflight, qemu, schemas, ssh

# ---------------------------------------------------------------------------
# Moved from tests/test_round2.py (round-2 dissolution).
# ---------------------------------------------------------------------------


def _fake_handle(pid: int = 4242) -> qemu.QemuHandle:
    proc = MagicMock()
    proc.pid = pid
    proc.poll.return_value = 0
    proc.returncode = 0
    return qemu.QemuHandle(
        proc=proc,
        serial_log_path=Path("/tmp/serial.log"),
        pgid=pid,
        started_at=0.0,
    )


def _fake_ssh_ok(target, cmd, timeout_s=120.0):
    return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")


def _required_counters_text() -> str:
    from harness import schemas as _s

    return "\n".join(f"{k} = {i}" for i, k in enumerate(_s.REQUIRED_COUNTER_KEYS)) + "\n"


def _valid_funcs_text() -> str:
    return (
        "stats for lua-lsm (ns)\n"
        "num name                         nlsm        "
        "count           total    average      maxtime\n"
        "----\n"
        "  1 inode_permission             1           5               500      100         200\n"
    )


def _perf_inputs(art: Path, rootfs: Path) -> cell_runner.CellInputs:
    return cell_runner.CellInputs(
        cell_id="perf_cell",
        profile={"kind": "perf"},
        workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench"),
        workload_name="bench",
        launcher=Path("/nonexistent/run.sh"),
        artifact_dir=art,
        ssh_target=ssh.SshTarget(
            host="127.0.0.1", port=10024, user="root", key_path=Path("/dev/null")
        ),
        kvm_required=False,
        rootfs_image=rootfs,
    )


def test_perf_cell_skips_with_image_not_warm_and_never_spawns(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    art = tdp / "perf"
    rootfs = tdp / "rootfs.img"
    rootfs.write_bytes(b"")
    # No `<rootfs>.warm-marker` -> preflight must skip.

    def _fail_spawn(*a, **kw):
        raise AssertionError("qemu.spawn must not be invoked for a cold-rootfs perf cell")

    inputs = _perf_inputs(art, rootfs)
    monkeypatch.setattr(qemu, "spawn", _fail_spawn)
    out = cell_runner.run_cell(inputs)
    assert out["verdict"] == "skip:image-not-warm"
    assert (art / "result.json").exists()
    # Perf payload must remain the schema's null default (no snapshots
    # were taken) so consumers can distinguish a skipped perf cell from
    # one with measured deltas.
    assert out["perf"].get("snapshots") is None
    assert out["perf"].get("deltas") is None


def test_perf_cell_proceeds_when_warm_marker_present(tmp_path, monkeypatch, linux_host):
    # Marker present -> the preflight gate must NOT short-circuit and
    # qemu.spawn must be reached. We mock the spawn to fail cleanly so we
    # can detect the gate decision without booting a real VM.
    tdp = tmp_path
    art = tdp / "perf"
    rootfs = tdp / "rootfs.img"
    rootfs.write_bytes(b"")
    preflight.default_warm_marker(rootfs).write_text("warm\n")
    sentinel = []

    def _spawn_sentinel(*a, **kw):
        sentinel.append(True)
        raise qemu.QemuLaunchError("test-only: stopped before boot")

    inputs = _perf_inputs(art, rootfs)
    monkeypatch.setattr(qemu, "spawn", _spawn_sentinel)
    out = cell_runner.run_cell(inputs)
    assert sentinel, "qemu.spawn must be reached when marker exists"
    # The harness-error verdict comes from the simulated launch failure.
    assert out["verdict"] == "harness-error"


def test_bughunt_cell_ignores_warm_marker(tmp_path, monkeypatch, linux_host):
    # Image warmth only gates perf cells; bughunt must NOT skip on a cold
    # rootfs (correctness cells boot a fresh kernel deliberately).
    tdp = tmp_path
    art = tdp / "bug"
    rootfs = tdp / "rootfs.img"
    rootfs.write_bytes(b"")
    inputs = cell_runner.CellInputs(
        cell_id="bug_cell",
        profile={"kind": "bughunt"},
        workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
        workload_name="noop",
        launcher=Path("/nonexistent/run.sh"),
        artifact_dir=art,
        ssh_target=ssh.SshTarget(
            host="127.0.0.1", port=10025, user="root", key_path=Path("/dev/null")
        ),
        kvm_required=False,
        rootfs_image=rootfs,
    )
    spawn_calls = []

    def _spawn_count(*a, **kw):
        spawn_calls.append(True)
        raise qemu.QemuLaunchError("test-only")

    monkeypatch.setattr(qemu, "spawn", _spawn_count)
    out = cell_runner.run_cell(inputs)
    assert spawn_calls, "bughunt cell must still attempt qemu.spawn"
    assert out["verdict"] != "skip:image-not-warm"


def _perf_inputs_warm(art: Path, rootfs: Path) -> cell_runner.CellInputs:
    # Pre-warm the rootfs so the image-warm gate (the *other* perf
    # preflight) does not steal the test's intent.
    preflight.default_warm_marker(rootfs).write_text("warm\n")
    return cell_runner.CellInputs(
        cell_id="perf_cell",
        profile={"kind": "perf"},
        workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench"),
        workload_name="bench",
        launcher=Path("/nonexistent/run.sh"),
        artifact_dir=art,
        ssh_target=ssh.SshTarget(
            host="127.0.0.1", port=10026, user="root", key_path=Path("/dev/null")
        ),
        kvm_required=False,
        rootfs_image=rootfs,
    )


def _run_perf_with_fetch(
    art: Path,
    rootfs: Path,
    stats_text: str | None,
    funcs_text: str | None,
    workload_invoked: list[bool],
    monkeypatch,
) -> dict:
    inputs = _perf_inputs_warm(art, rootfs)

    def _wl(target, ctx):
        workload_invoked.append(True)
        return cell_runner.WorkloadResult(name="bench", returncode=0)

    # Replace the workload with our sentinel so we can detect whether
    # the strict-both gate skipped the workload.
    inputs = cell_runner.CellInputs(
        **{**inputs.__dict__, "workload_fn": _wl},
    )

    fetch_iter = iter([(stats_text, funcs_text), (stats_text, funcs_text)])

    def _fetch_pair(target):
        try:
            return next(fetch_iter)
        except StopIteration:
            return (stats_text, funcs_text)

    monkeypatch.setattr(qemu, "spawn", lambda *a, **kw: _fake_handle())
    monkeypatch.setattr(qemu, "stop", lambda *a, **kw: 0)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: True)
    monkeypatch.setattr(ssh, "run", _fake_ssh_ok)
    monkeypatch.setattr(cell_runner, "_fetch_perf_texts", _fetch_pair)
    return cell_runner.run_cell(inputs)


def _stats_text() -> str:
    # Use the real REQUIRED_COUNTER_KEYS so the strict validator accepts
    # the snapshot. AC-5.1 requires every key in REQUIRED_COUNTER_KEYS to
    # be present before a perf cell is considered measurable.
    lines = [f"{k} = {i}" for i, k in enumerate(schemas.REQUIRED_COUNTER_KEYS)]
    return "\n".join(lines) + "\n"


def _funcs_text() -> str:
    return (
        "stats for lua-lsm (ns)\n"
        "num name                         nlsm        "
        "count           total    average      maxtime\n"
        "----\n"
        "  1 inode_permission             1           "
        "5               500      100         200\n"
    )


def test_perf_skip_when_only_stats_present(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    art = tdp / "perf"
    rootfs = tdp / "rootfs.img"
    rootfs.write_bytes(b"")
    workload_invoked: list[bool] = []
    out = _run_perf_with_fetch(
        art,
        rootfs,
        stats_text=_stats_text(),
        funcs_text=None,
        workload_invoked=workload_invoked,
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "skip:stats-unavailable"
    assert not workload_invoked, "workload must not run when perf preflight skips"
    assert out["perf"].get("snapshots") is None
    assert out["perf"].get("deltas") is None


def test_perf_skip_when_only_lsm_funcs_present(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    art = tdp / "perf"
    rootfs = tdp / "rootfs.img"
    rootfs.write_bytes(b"")
    workload_invoked: list[bool] = []
    out = _run_perf_with_fetch(
        art,
        rootfs,
        stats_text=None,
        funcs_text=_funcs_text(),
        workload_invoked=workload_invoked,
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "skip:stats-unavailable"
    assert not workload_invoked
    assert out["perf"].get("snapshots") is None
    assert out["perf"].get("deltas") is None


def test_perf_skip_when_both_missing(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    art = tdp / "perf"
    rootfs = tdp / "rootfs.img"
    rootfs.write_bytes(b"")
    workload_invoked: list[bool] = []
    out = _run_perf_with_fetch(
        art,
        rootfs,
        stats_text=None,
        funcs_text=None,
        workload_invoked=workload_invoked,
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "skip:stats-unavailable"
    assert not workload_invoked
    assert out["perf"].get("snapshots") is None
    assert out["perf"].get("deltas") is None


def test_perf_runs_when_both_present(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    art = tdp / "perf"
    rootfs = tdp / "rootfs.img"
    rootfs.write_bytes(b"")
    (art).mkdir(parents=True, exist_ok=True)
    (art / "dmesg.log").write_text("[    0.000] Linux version 6.10\n")
    workload_invoked: list[bool] = []
    out = _run_perf_with_fetch(
        art,
        rootfs,
        stats_text=_stats_text(),
        funcs_text=_funcs_text(),
        workload_invoked=workload_invoked,
        monkeypatch=monkeypatch,
    )
    assert workload_invoked, "workload must run when both files present"
    assert "skip:stats-unavailable" not in str(out.get("verdict"))
    assert out.get("perf") is not None


# Drive `run_cell` end-to-end with mocked SSH/QEMU and feed it
# intentionally-malformed perf telemetry for either the before-snapshot or
# the after-snapshot. The strict path MUST reject both forms with
# skip:stats-unavailable; the workload MUST NOT see partial-delta passes.


def _perf_inputs_warm_rc0(art: Path, rootfs: Path) -> cell_runner.CellInputs:
    preflight.default_warm_marker(rootfs).write_text("warm\n")
    return cell_runner.CellInputs(
        cell_id="perf_cell",
        profile={"kind": "perf"},
        workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench", returncode=0),
        workload_name="bench",
        launcher=Path("/nonexistent/run.sh"),
        artifact_dir=art,
        ssh_target=ssh.SshTarget(
            host="127.0.0.1", port=10027, user="root", key_path=Path("/dev/null")
        ),
        kvm_required=False,
        rootfs_image=rootfs,
    )


def _run(
    art: Path,
    rootfs: Path,
    before_pair: tuple[str | None, str | None],
    after_pair: tuple[str | None, str | None],
    monkeypatch,
) -> dict:
    inputs = _perf_inputs_warm_rc0(art, rootfs)
    workload_invoked: list[bool] = []

    def _wl(target, ctx):
        workload_invoked.append(True)
        return cell_runner.WorkloadResult(name="bench", returncode=0)

    inputs = cell_runner.CellInputs(
        **{**inputs.__dict__, "workload_fn": _wl},
    )

    # First _fetch_perf_texts call is BEFORE, second is AFTER. Any further
    # call (defensive) returns the after pair so we don't trip StopIteration.
    pairs = iter([before_pair, after_pair])

    def _fetch(target):
        try:
            return next(pairs)
        except StopIteration:
            return after_pair

    art.mkdir(parents=True, exist_ok=True)
    (art / "dmesg.log").write_text("[    0.000] Linux version 6.10\n")

    monkeypatch.setattr(qemu, "spawn", lambda *a, **kw: _fake_handle())
    monkeypatch.setattr(qemu, "stop", lambda *a, **kw: 0)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: True)
    monkeypatch.setattr(ssh, "run", _fake_ssh_ok)
    monkeypatch.setattr(cell_runner, "_fetch_perf_texts", _fetch)
    result = cell_runner.run_cell(inputs)
    result["__workload_invoked__"] = bool(workload_invoked)
    return result


def test_malformed_before_counters_skips_without_workload_spawn(tmp_path, monkeypatch, linux_host):
    bad_stats = "lvm.alloc_count = 1\nlvm.alloc_total_ns = 1000\n"  # not REQUIRED keys
    tdp = tmp_path
    out = _run(
        tdp / "perf",
        tdp / "rootfs.img",
        before_pair=(bad_stats, _valid_funcs_text()),
        after_pair=(_required_counters_text(), _valid_funcs_text()),
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "skip:stats-unavailable"
    assert "malformed" in out["reason"]
    assert not out["__workload_invoked__"], (
        "workload must not run when before-snapshot is malformed"
    )
    assert out["perf"].get("snapshots") is None
    assert out["perf"].get("deltas") is None


def test_malformed_before_lsm_funcs_skips_without_workload_spawn(tmp_path, monkeypatch, linux_host):
    empty_funcs = "stats for lua-lsm (ns)\n"  # header only, no rows
    tdp = tmp_path
    out = _run(
        tdp / "perf",
        tdp / "rootfs.img",
        before_pair=(_required_counters_text(), empty_funcs),
        after_pair=(_required_counters_text(), _valid_funcs_text()),
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "skip:stats-unavailable"
    assert not out["__workload_invoked__"]
    assert out["perf"].get("snapshots") is None


def test_malformed_after_counters_skips_no_partial_deltas(tmp_path, monkeypatch, linux_host):
    bad_stats = "lvm.alloc_count = 1\n"
    tdp = tmp_path
    out = _run(
        tdp / "perf",
        tdp / "rootfs.img",
        before_pair=(_required_counters_text(), _valid_funcs_text()),
        after_pair=(bad_stats, _valid_funcs_text()),
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "skip:stats-unavailable", f"got verdict={out.get('verdict')!r}"
    assert out["__workload_invoked__"], "workload runs when before-snapshot is valid"
    assert "malformed" in out["reason"]
    assert out["perf"].get("snapshots") is None, (
        "malformed-after must NOT emit partial-delta snapshots"
    )
    assert out["perf"].get("deltas") is None


def test_malformed_after_lsm_funcs_skips_no_partial_deltas(tmp_path, monkeypatch, linux_host):
    empty_funcs = "stats for lua-lsm (ns)\n"
    tdp = tmp_path
    out = _run(
        tdp / "perf",
        tdp / "rootfs.img",
        before_pair=(_required_counters_text(), _valid_funcs_text()),
        after_pair=(_required_counters_text(), empty_funcs),
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "skip:stats-unavailable"
    assert out["__workload_invoked__"]
    assert out["perf"].get("snapshots") is None
    assert out["perf"].get("deltas") is None


def test_valid_both_sides_produces_full_deltas_and_pass(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    out = _run(
        tdp / "perf",
        tdp / "rootfs.img",
        before_pair=(_required_counters_text(), _valid_funcs_text()),
        after_pair=(_required_counters_text(), _valid_funcs_text()),
        monkeypatch=monkeypatch,
    )
    assert out["verdict"] == "pass", f"got verdict={out.get('verdict')!r}"
    assert out["perf"]["snapshots"] is not None
    assert "before" in out["perf"]["snapshots"]
    assert "after" in out["perf"]["snapshots"]
    assert out["perf"]["deltas"] is not None
