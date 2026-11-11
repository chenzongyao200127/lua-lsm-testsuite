import json
import signal
import subprocess
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from harness import __main__ as cli
from harness import cell_runner, hostenv, matrix, qemu, run_registry, schemas, ssh


class ExpandTests(unittest.TestCase):
    def test_expand_cartesian_product(self):
        plan = matrix.expand(
            {
                "name": "demo",
                "axes": {
                    "kind": ["perf", "bughunt"],
                    "pool_max": [4, 16],
                },
            }
        )
        self.assertEqual(len(plan), 4)
        kinds = sorted({c.profile["kind"] for c in plan})
        self.assertEqual(kinds, ["bughunt", "perf"])

    def test_expand_with_exclude(self):
        plan = matrix.expand(
            {
                "name": "demo",
                "axes": {"kind": ["perf", "bughunt"], "pool_max": [4, 16]},
                "exclude": [{"kind": "perf", "pool_max": 4}],
            }
        )
        self.assertEqual(len(plan), 3)
        for c in plan:
            self.assertFalse(c.profile["kind"] == "perf" and c.profile["pool_max"] == 4)

    def test_expand_no_axes_emits_default_cell(self):
        plan = matrix.expand({"name": "demo", "defaults": {"kvm_required": True}})
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0].profile["kvm_required"], True)

    def test_expand_workload_default_propagates(self):
        plan = matrix.expand(
            {
                "name": "demo",
                "workload": "bench",
                "axes": {"k": [1, 2]},
            }
        )
        self.assertTrue(all(c.workload == "bench" for c in plan))

    def test_smoke_matrix_has_32_cells(self):
        # DEC-5 hard requirement: minimal smoke matrix is exactly 32 cells.
        # Use the JSON variant when PyYAML is unavailable; both must agree.
        configs = Path(__file__).resolve().parent.parent / "configs"
        path = configs / "smoke.json"
        plan = matrix.plan_from_file(path)
        self.assertEqual(
            len(plan.cells), 32, f"smoke matrix expanded to {len(plan.cells)} cells, expected 32"
        )

    def test_smoke_matrix_exposes_dec5_axes(self):
        """DEC-5: the default smoke sweep is policy x lvm_pool_max x
        kconfig_profile x workload, with the documented value sets."""
        configs = Path(__file__).resolve().parent.parent / "configs"
        plan = matrix.plan_from_file(configs / "smoke.json")
        policies = sorted({c.profile["policy"] for c in plan.cells})
        pools = sorted({c.profile["lvm_pool_max"] for c in plan.cells})
        profiles = sorted({c.profile["kconfig_profile"] for c in plan.cells})
        workloads_seen = sorted({c.profile["workload"] for c in plan.cells})
        self.assertEqual(policies, ["denyfile", "exectl", "hello", "pindown"])
        self.assertEqual(pools, [0, 32])
        self.assertEqual(profiles, ["full", "standard"])
        self.assertEqual(workloads_seen, ["bench-short", "smoke"])

    def test_perf_matrix_carries_policy_default(self):
        """Round 5 / AC-5.1: every cell expanded from configs/perf.yaml
        must carry a non-empty `policy` profile knob so the UnixBench
        workload's register step has a real policy file to install."""
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed; skip perf.yaml policy default check")
        configs = Path(__file__).resolve().parent.parent / "configs"
        plan = matrix.plan_from_file(configs / "perf.yaml")
        self.assertGreater(len(plan.cells), 0, "perf matrix expanded to zero cells")
        for c in plan.cells:
            self.assertIn("policy", c.profile, f"perf cell {c.cell_id} is missing a `policy` knob")
            self.assertTrue(c.profile["policy"], f"perf cell {c.cell_id} has empty policy")

    def test_smoke_matrix_yaml_and_json_agree(self):
        """Both shipped smoke configs must expand to the same 32 cell ids so
        the two formats stay in lock-step for environments without PyYAML."""
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed; skip YAML/JSON cross-check")
        configs = Path(__file__).resolve().parent.parent / "configs"
        ids_yaml = sorted(c.cell_id for c in matrix.plan_from_file(configs / "smoke.yaml").cells)
        ids_json = sorted(c.cell_id for c in matrix.plan_from_file(configs / "smoke.json").cells)
        self.assertEqual(ids_yaml, ids_json)


class ExecutorTests(unittest.TestCase):
    def test_run_matrix_aggregates_totals_and_writes_json(self):
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

        with TemporaryDirectory() as td:
            opts = matrix.ExecutorOpts(parallel=2, runs_root=Path(td), port_base=10100)
            m = matrix.run_matrix(plan, opts, fake_runner)
            self.assertEqual(m["totals"]["passed"], 1)
            self.assertEqual(m["totals"]["failed"], 1)
            self.assertEqual(m["totals"]["skipped"], 1)
            # The matrix.json is written under runs_root/<utc-id>/matrix.json.
            json_files = list(Path(td).rglob("matrix.json"))
            self.assertEqual(len(json_files), 1)
            on_disk = json.loads(json_files[0].read_text())
            self.assertEqual(on_disk["totals"]["passed"], 1)
            # Port allocator handed out distinct ports starting at port_base.
            self.assertEqual(sorted(seen_ports), [10100, 10101, 10102])


class PortAllocTests(unittest.TestCase):
    def test_allocate_ports_default_base(self):
        ports = matrix.allocate_ports(3)
        self.assertEqual(ports, [10023, 10024, 10025])

    def test_allocate_ports_custom_base(self):
        self.assertEqual(matrix.allocate_ports(2, base=12000), [12000, 12001])

    def test_allocate_ports_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            matrix.allocate_ports(10, base=65530)


class ShareDirTests(unittest.TestCase):
    def test_share_dir_refuses_missing_lua_lsm_tools(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "kernel" / "linux").mkdir(parents=True)
            with self.assertRaises(matrix.ShareDirError):
                matrix.assert_share_dir(tdp)

    def test_share_dir_accepts_valid_workspace(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "lua-lsm-tools").mkdir(parents=True)
            (tdp / "kernel" / "linux").mkdir(parents=True)
            matrix.assert_share_dir(tdp)  # no exception

    def test_share_dir_requirement_is_workload_aware(self):
        self.assertEqual(
            matrix.required_share_entries(["functional"]),
            ("lua-lsm-testsuite",),
        )
        self.assertEqual(
            matrix.required_share_entries(["functional", "smoke"]),
            matrix.REQUIRED_SHARE_ENTRIES,
        )


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Moved verbatim from tests/test_round2.py (round-2 dissolution).
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


class _PatchHostEnv:
    def __enter__(self):
        self._patch = patch.object(
            hostenv,
            "detect",
            return_value=hostenv.HostEnv(system="Linux", release="6.10.0", has_kvm=True),
        )
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()


class SigintReapTests(unittest.TestCase):
    def test_sigint_stops_registered_handle_within_grace(self):
        # Mock the qemu.stop path with an instrumented spy so we can verify
        # registry.stop_all called it during the SIGINT handler. Use a serial
        # runner with two cells so we can SIGINT after the first one starts.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            registry = run_registry.RunRegistry()
            handle = _fake_handle()
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
                    matrix.CellSpec(
                        cell_id="cell-a", profile={"workload": "smoke"}, workload="smoke"
                    ),
                ],
            )
            opts = matrix.ExecutorOpts(
                parallel=1,
                runs_root=tdp / "runs",
                matrix_path=None,
                port_base=20000,
                registry=registry,
            )
            with patch.object(qemu, "stop", return_value=0) as stop_mock:
                matrix.run_matrix(plan, opts, _slow_runner)
            stop_mock.assert_called()
            self.assertTrue(
                stopped_in_handler and stopped_in_handler[0],
                "registry.stop_all should have removed cell-a",
            )


class MatrixKconfigValidationTests(unittest.TestCase):
    def _write_matrix(self, td: Path, doc_text: str) -> Path:
        cfg = td / "matrix.json"
        cfg.write_text(doc_text)
        return cfg

    def test_matrix_with_invalid_profile_in_axis_fails_before_runs_dir(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = self._write_matrix(
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
            with _PatchHostEnv():
                rc = cli.main(args)
            self.assertEqual(
                rc, cli.KSFT_FAIL, "matrix with bogus kconfig profile must fail at planning"
            )
            self.assertFalse(
                (tdp / "runs").exists(), "runs dir must not be created when a profile is invalid"
            )

    def test_build_kernel_invoked_once_per_distinct_profile(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            # Two cells, two distinct profiles: helper must be called exactly
            # twice with `--kernel <tree> --profile <X>` matching the real
            # enable-debug-kconfig.sh contract (it requires --kernel <dir>).
            cfg = self._write_matrix(
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

            with (
                _PatchHostEnv(),
                patch.object(cli.subprocess, "run", side_effect=_fake_subprocess_run),
                patch.object(qemu, "spawn", return_value=_fake_handle()),
                patch.object(qemu, "stop", return_value=0),
                patch.object(ssh, "wait_for_ssh", return_value=True),
                patch.object(ssh, "run", side_effect=_fake_ssh_ok),
                patch(
                    "harness.workloads.by_name",
                    return_value=lambda t, c: cell_runner.WorkloadResult(name="smoke"),
                ),
            ):
                cli.main(args)

            helper_calls = [c for c in run_calls if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(
                len(helper_calls),
                2,
                f"helper should be invoked once per distinct profile, got {helper_calls!r}",
            )
            # Every helper invocation MUST carry --kernel <tree> AND --profile <X>
            for call in helper_calls:
                self.assertIn("--kernel", call, f"helper call must include --kernel: {call!r}")
                kernel_idx = call.index("--kernel")
                self.assertEqual(
                    call[kernel_idx + 1],
                    str(kernel_tree),
                    f"--kernel argument should be {kernel_tree}: {call!r}",
                )
                self.assertIn("--profile", call, f"helper call must include --profile: {call!r}")
            seen_profiles = sorted(c[c.index("--profile") + 1] for c in helper_calls)
            self.assertEqual(seen_profiles, ["full", "standard"])

    def test_build_kernel_invoked_once_when_single_distinct_profile(self):
        # When the matrix repeats the same profile across many cells, the
        # helper must still run only once -- and still carry --kernel.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = self._write_matrix(
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

            with (
                _PatchHostEnv(),
                patch.object(cli.subprocess, "run", side_effect=_fake_subprocess_run),
                patch.object(qemu, "spawn", return_value=_fake_handle()),
                patch.object(qemu, "stop", return_value=0),
                patch.object(ssh, "wait_for_ssh", return_value=True),
                patch.object(ssh, "run", side_effect=_fake_ssh_ok),
                patch(
                    "harness.workloads.by_name",
                    return_value=lambda t, c: cell_runner.WorkloadResult(name="smoke"),
                ),
            ):
                cli.main(args)

            helper_calls = [c for c in run_calls if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(
                len(helper_calls),
                1,
                f"helper should run exactly once for one distinct profile, got {helper_calls!r}",
            )
            call = helper_calls[0]
            self.assertIn("--kernel", call)
            self.assertEqual(call[call.index("--kernel") + 1], str(kernel_tree))
            self.assertEqual(call[call.index("--profile") + 1], "standard")


class MatrixSigintCancelTests(unittest.TestCase):
    def test_sigint_cancels_queued_cells_and_runs_complete_fast(self):
        import os

        with TemporaryDirectory() as td:
            tdp = Path(td)
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
            self.assertEqual(len(passes), 2, f"exactly two workers were in flight, got {verdicts}")
            self.assertEqual(
                len(aborts), 6, f"the six queued cells must abort after SIGINT, got {verdicts}"
            )
            # Aborted cells still get a result.json on disk so a triage script
            # can see the full plan.
            runs_subdirs = list((tdp / "runs").iterdir())
            self.assertEqual(len(runs_subdirs), 1, "expected exactly one timestamped runs subdir")
            for cid in aborts:
                self.assertTrue(
                    (runs_subdirs[0] / cid / "result.json").exists(),
                    f"missing result.json for aborted cell {cid}",
                )
