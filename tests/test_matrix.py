import json
import signal
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from harness import __main__ as cli
from harness import cell_runner, matrix, qemu, run_registry, schemas, ssh


def test_expand_cartesian_product():
    plan = matrix.expand(
        {
            "name": "demo",
            "axes": {
                "kind": ["perf", "bughunt"],
                "pool_max": [4, 16],
            },
        }
    )
    assert len(plan) == 4
    kinds = sorted({c.profile["kind"] for c in plan})
    assert kinds == ["bughunt", "perf"]


def test_expand_with_exclude():
    plan = matrix.expand(
        {
            "name": "demo",
            "axes": {"kind": ["perf", "bughunt"], "pool_max": [4, 16]},
            "exclude": [{"kind": "perf", "pool_max": 4}],
        }
    )
    assert len(plan) == 3
    for c in plan:
        assert not (c.profile["kind"] == "perf" and c.profile["pool_max"] == 4)


def test_expand_no_axes_emits_default_cell():
    plan = matrix.expand({"name": "demo", "defaults": {"kvm_required": True}})
    assert len(plan) == 1
    assert plan[0].profile["kvm_required"] is True


def test_expand_workload_default_propagates():
    plan = matrix.expand(
        {
            "name": "demo",
            "workload": "bench",
            "axes": {"k": [1, 2]},
        }
    )
    assert all(c.workload == "bench" for c in plan)


def test_smoke_matrix_has_32_cells():
    # DEC-5 hard requirement: minimal smoke matrix is exactly 32 cells.
    # Use the JSON variant when PyYAML is unavailable; both must agree.
    configs = Path(__file__).resolve().parent.parent / "configs"
    path = configs / "smoke.json"
    plan = matrix.plan_from_file(path)
    assert len(plan.cells) == 32, f"smoke matrix expanded to {len(plan.cells)} cells, expected 32"


def test_smoke_matrix_exposes_dec5_axes():
    """DEC-5: the default smoke sweep is policy x lvm_pool_max x
    kconfig_profile x workload, with the documented value sets."""
    configs = Path(__file__).resolve().parent.parent / "configs"
    plan = matrix.plan_from_file(configs / "smoke.json")
    policies = sorted({c.profile["policy"] for c in plan.cells})
    pools = sorted({c.profile["lvm_pool_max"] for c in plan.cells})
    profiles = sorted({c.profile["kconfig_profile"] for c in plan.cells})
    workloads_seen = sorted({c.profile["workload"] for c in plan.cells})
    assert policies == ["denyfile", "exectl", "hello", "pindown"]
    assert pools == [0, 32]
    assert profiles == ["full", "standard"]
    assert workloads_seen == ["bench-short", "smoke"]


def test_perf_matrix_carries_policy_default():
    """Round 5 / AC-5.1: every cell expanded from configs/perf.yaml
    must carry a non-empty `policy` profile knob so the UnixBench
    workload's register step has a real policy file to install."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML not installed; skip perf.yaml policy default check")
    configs = Path(__file__).resolve().parent.parent / "configs"
    plan = matrix.plan_from_file(configs / "perf.yaml")
    assert len(plan.cells) > 0, "perf matrix expanded to zero cells"
    for c in plan.cells:
        assert "policy" in c.profile, f"perf cell {c.cell_id} is missing a `policy` knob"
        assert c.profile["policy"], f"perf cell {c.cell_id} has empty policy"


def test_smoke_matrix_yaml_and_json_agree():
    """Both shipped smoke configs must expand to the same 32 cell ids so
    the two formats stay in lock-step for environments without PyYAML."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML not installed; skip YAML/JSON cross-check")
    configs = Path(__file__).resolve().parent.parent / "configs"
    ids_yaml = sorted(c.cell_id for c in matrix.plan_from_file(configs / "smoke.yaml").cells)
    ids_json = sorted(c.cell_id for c in matrix.plan_from_file(configs / "smoke.json").cells)
    assert ids_yaml == ids_json


def test_run_matrix_aggregates_totals_and_writes_json(tmp_path):
    plan = matrix.MatrixPlan(
        name="demo",
        cells=[
            matrix.CellSpec(cell_id="c1", profile={"k": 1}, workload="smoke"),
            matrix.CellSpec(cell_id="c2", profile={"k": 2}, workload="smoke"),
            matrix.CellSpec(cell_id="c3", profile={"k": 3}, workload="smoke"),
        ],
    )

    verdicts = {"c1": "pass", "c2": "kernel-bug", "c3": "skip:no-kvm"}
    seen_ports: list[int] = []

    def fake_runner(cell, artifact_dir, port):
        seen_ports.append(port)
        return {
            "schema_version": 1,
            "cell_id": cell.cell_id,
            "verdict": verdicts[cell.cell_id],
            "started_at": "2026-05-27T00:00:00+00:00",
            "finished_at": "2026-05-27T00:00:01+00:00",
        }

    opts = matrix.ExecutorOpts(parallel=2, runs_root=tmp_path, port_base=10100)
    m = matrix.run_matrix(plan, opts, fake_runner)
    assert m["totals"]["passed"] == 1
    assert m["totals"]["failed"] == 1
    assert m["totals"]["skipped"] == 1
    # The matrix.json is written under runs_root/<utc-id>/matrix.json.
    json_files = list(tmp_path.rglob("matrix.json"))
    assert len(json_files) == 1
    on_disk = json.loads(json_files[0].read_text())
    assert on_disk["totals"]["passed"] == 1
    # Port allocator handed out distinct ports starting at port_base.
    assert sorted(seen_ports) == [10100, 10101, 10102]


def test_allocate_ports_default_base():
    ports = matrix.allocate_ports(3)
    assert ports == [10023, 10024, 10025]


def test_allocate_ports_custom_base():
    assert matrix.allocate_ports(2, base=12000) == [12000, 12001]


def test_allocate_ports_rejects_out_of_range():
    with pytest.raises(ValueError):
        matrix.allocate_ports(10, base=65530)


def test_share_dir_refuses_missing_lua_lsm_tools(tmp_path):
    tdp = tmp_path
    (tdp / "kernel" / "linux").mkdir(parents=True)
    with pytest.raises(matrix.ShareDirError):
        matrix.assert_share_dir(tdp)


def test_share_dir_accepts_valid_workspace(tmp_path):
    tdp = tmp_path
    (tdp / "lua-lsm-tools").mkdir(parents=True)
    (tdp / "kernel" / "linux").mkdir(parents=True)
    matrix.assert_share_dir(tdp)  # no exception


def test_share_dir_requirement_is_workload_aware():
    assert matrix.required_share_entries(["functional"]) == ("lua-lsm-testsuite",)
    assert matrix.required_share_entries(["functional", "smoke"]) == matrix.REQUIRED_SHARE_ENTRIES


# ---------------------------------------------------------------------------
# Moved from tests/test_round2.py (round-2 dissolution).
# ---------------------------------------------------------------------------


def test_sigint_stops_registered_handle_within_grace(tmp_path, monkeypatch, fake_qemu_handle):
    # Mock the qemu.stop path with an instrumented spy so we can verify
    # registry.stop_all called it during the SIGINT handler. Use a serial
    # runner with two cells so we can SIGINT after the first one starts.
    tdp = tmp_path
    registry = run_registry.RunRegistry()
    handle = fake_qemu_handle()
    registry.register("cell-a", handle)

    stopped_in_handler: list[bool] = []

    def _slow_runner(cell, art, port):
        # Simulate the harness landing in the workload when SIGINT arrives.
        # We send SIGINT into our own process, which the matrix executor
        # has armed with _on_sigint, then assert the registry reaped.
        import os

        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)
        stopped_in_handler.append("cell-a" not in registry.active_cells())
        art.mkdir(parents=True, exist_ok=True)
        return schemas.empty_result(cell.cell_id)

    plan = matrix.MatrixPlan(
        name="m",
        cells=[
            matrix.CellSpec(cell_id="cell-a", profile={"workload": "smoke"}, workload="smoke"),
        ],
    )
    opts = matrix.ExecutorOpts(
        parallel=1,
        runs_root=tdp / "runs",
        matrix_path=None,
        port_base=20000,
        registry=registry,
    )
    stop_mock = MagicMock(return_value=0)
    monkeypatch.setattr(qemu, "stop", stop_mock)
    matrix.run_matrix(plan, opts, _slow_runner)
    stop_mock.assert_called()
    assert stopped_in_handler and stopped_in_handler[0], (
        "registry.stop_all should have removed cell-a"
    )


def _write_matrix(td: Path, doc_text: str) -> Path:
    cfg = td / "matrix.json"
    cfg.write_text(doc_text)
    return cfg


def test_matrix_with_invalid_profile_in_axis_fails_before_runs_dir(tmp_path, linux_host):
    tdp = tmp_path
    cfg = _write_matrix(
        tdp,
        json.dumps(
            {
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt"},
                "axes": {"kconfig_profile": ["standard", "bogus"]},
            }
        ),
    )
    args = [
        "matrix",
        "--config",
        str(cfg),
        "--runs-root",
        str(tdp / "runs"),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/run.sh",
    ]
    rc = cli.main(args)
    assert rc == cli.KSFT_FAIL, "matrix with bogus kconfig profile must fail at planning"
    assert not (tdp / "runs").exists(), "runs dir must not be created when a profile is invalid"


def test_build_kernel_invoked_once_per_distinct_profile(
    tmp_path, monkeypatch, linux_host, fake_qemu_handle, fake_ssh
):
    tdp = tmp_path
    # Two cells, two distinct profiles: helper must be called exactly
    # twice with `--kernel <tree> --profile <X>` matching the real
    # enable-debug-kconfig.sh contract (it requires --kernel <dir>).
    cfg = _write_matrix(
        tdp,
        json.dumps(
            {
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt"},
                "axes": {"kconfig_profile": ["standard", "full"]},
            }
        ),
    )
    debug_kernel = tdp / "tools"
    debug_kernel.mkdir()
    helper = debug_kernel / "enable-debug-kconfig.sh"
    helper.write_text("#!/bin/sh\nexit 0\n")
    helper.chmod(0o755)
    kernel_tree = tdp / "linux"
    kernel_tree.mkdir()

    args = [
        "matrix",
        "--config",
        str(cfg),
        "--runs-root",
        str(tdp / "runs"),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/run.sh",
        "--debug-kernel",
        str(debug_kernel),
        "--kernel-tree",
        str(kernel_tree),
        "--build-kernel",
        "--parallel",
        "1",
        # Workload mocks so we never actually try to boot.
    ]

    run_calls: list[list[str]] = []

    def _fake_subprocess_run(cmd, *a, **kw):
        run_calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(cli.subprocess, "run", _fake_subprocess_run)
    monkeypatch.setattr(qemu, "spawn", lambda *a, **kw: fake_qemu_handle())
    monkeypatch.setattr(qemu, "stop", lambda *a, **kw: 0)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: True)
    monkeypatch.setattr(
        "harness.workloads.by_name",
        lambda *a, **kw: lambda t, c: cell_runner.WorkloadResult(name="smoke"),
    )
    cli.main(args)

    helper_calls = [c for c in run_calls if str(c[0]).endswith("enable-debug-kconfig.sh")]
    assert len(helper_calls) == 2, (
        f"helper should be invoked once per distinct profile, got {helper_calls!r}"
    )
    # Every helper invocation MUST carry --kernel <tree> AND --profile <X>
    for call in helper_calls:
        assert "--kernel" in call, f"helper call must include --kernel: {call!r}"
        kernel_idx = call.index("--kernel")
        assert call[kernel_idx + 1] == str(kernel_tree), (
            f"--kernel argument should be {kernel_tree}: {call!r}"
        )
        assert "--profile" in call, f"helper call must include --profile: {call!r}"
    seen_profiles = sorted(c[c.index("--profile") + 1] for c in helper_calls)
    assert seen_profiles == ["full", "standard"]


def test_build_kernel_invoked_once_when_single_distinct_profile(
    tmp_path, monkeypatch, linux_host, fake_qemu_handle, fake_ssh
):
    # When the matrix repeats the same profile across many cells, the
    # helper must still run only once -- and still carry --kernel.
    tdp = tmp_path
    cfg = _write_matrix(
        tdp,
        json.dumps(
            {
                "name": "m",
                "defaults": {
                    "workload": "smoke",
                    "kind": "bughunt",
                    "kconfig_profile": "standard",
                },
                "axes": {"lvm_pool_max": [4, 8, 16]},
            }
        ),
    )
    debug_kernel = tdp / "tools"
    debug_kernel.mkdir()
    helper = debug_kernel / "enable-debug-kconfig.sh"
    helper.write_text("#!/bin/sh\nexit 0\n")
    helper.chmod(0o755)
    kernel_tree = tdp / "linux"
    kernel_tree.mkdir()
    args = [
        "matrix",
        "--config",
        str(cfg),
        "--runs-root",
        str(tdp / "runs"),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/run.sh",
        "--debug-kernel",
        str(debug_kernel),
        "--kernel-tree",
        str(kernel_tree),
        "--build-kernel",
    ]
    run_calls: list[list[str]] = []

    def _fake_subprocess_run(cmd, *a, **kw):
        run_calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(cli.subprocess, "run", _fake_subprocess_run)
    monkeypatch.setattr(qemu, "spawn", lambda *a, **kw: fake_qemu_handle())
    monkeypatch.setattr(qemu, "stop", lambda *a, **kw: 0)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: True)
    monkeypatch.setattr(
        "harness.workloads.by_name",
        lambda *a, **kw: lambda t, c: cell_runner.WorkloadResult(name="smoke"),
    )
    cli.main(args)

    helper_calls = [c for c in run_calls if str(c[0]).endswith("enable-debug-kconfig.sh")]
    assert len(helper_calls) == 1, (
        f"helper should run exactly once for one distinct profile, got {helper_calls!r}"
    )
    call = helper_calls[0]
    assert "--kernel" in call
    assert call[call.index("--kernel") + 1] == str(kernel_tree)
    assert call[call.index("--profile") + 1] == "standard"


def test_sigint_cancels_queued_cells_and_runs_complete_fast(tmp_path):
    import os

    tdp = tmp_path
    cells = [
        matrix.CellSpec(cell_id=f"c{i}", profile={"kind": "bughunt"}, workload="smoke")
        for i in range(8)
    ]
    plan = matrix.MatrixPlan(name="sigint", cells=cells)
    # workers=2 forces the cf.ThreadPoolExecutor branch where futures
    # exist; workers=1 takes a serial path and would not exercise the
    # cancel-pending-futures fix.
    opts = matrix.ExecutorOpts(parallel=2, runs_root=tdp / "runs")

    workers_in = threading.Semaphore(0)
    release_blocker = threading.Event()

    def _runner(cell, art, port):
        # Block both workers until SIGINT lands; c2..c7 stay queued
        # in the threadpool and are cancellation targets.
        workers_in.release()
        release_blocker.wait(timeout=10.0)
        r = schemas.empty_result(cell.cell_id)
        r["verdict"] = "pass"
        r["finished_at"] = "2026-05-27T00:00:00+00:00"
        return r

    def _fire_sigint():
        # Wait until both workers are blocked inside _runner so the
        # remaining cells are queued (not in flight).
        workers_in.acquire(timeout=10.0)
        workers_in.acquire(timeout=10.0)
        os.kill(os.getpid(), signal.SIGINT)
        # Give the handler a moment to cancel queued futures, then
        # release the held workers so they can return their `pass`
        # results and the executor can drain.
        time.sleep(0.1)
        release_blocker.set()

    t = threading.Thread(target=_fire_sigint, daemon=True)
    t.start()
    try:
        result = matrix.run_matrix(plan, opts, _runner)
    finally:
        release_blocker.set()
        t.join(timeout=5.0)

    verdicts = {c["cell_id"]: c["verdict"] for c in result["cells"]}
    # The two cells that occupied the workers run to completion.
    passes = [cid for cid, v in verdicts.items() if v == "pass"]
    aborts = [cid for cid, v in verdicts.items() if v == "aborted"]
    assert len(passes) == 2, f"exactly two workers were in flight, got {verdicts}"
    assert len(aborts) == 6, f"the six queued cells must abort after SIGINT, got {verdicts}"
    # Aborted cells still get a result.json on disk so a triage script
    # can see the full plan.
    runs_subdirs = list((tdp / "runs").iterdir())
    assert len(runs_subdirs) == 1, "expected exactly one timestamped runs subdir"
    for cid in aborts:
        assert (runs_subdirs[0] / cid / "result.json").exists(), (
            f"missing result.json for aborted cell {cid}"
        )
