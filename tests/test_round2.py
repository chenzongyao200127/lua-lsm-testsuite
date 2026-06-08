"""Round-2 regression tests: detach/interactive modes, workload-fail verdict,
runtime bundle generation, SIGINT QEMU reap, kconfig validation, qemu OSError
wrap, and the LKDTM rc=77 short-circuit ordering.

These tests drive the harness end-to-end with QEMU/SSH mocked so the cell
runner, matrix executor, and CLI dispatcher all exercise their real code
paths but never spawn a real VM.
"""

from __future__ import annotations

import json
import signal
import subprocess
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from harness import (
    __main__ as cli, bundle, cell_runner, hostenv, matrix, preflight, qemu,
    run_registry, schemas, ssh,
)


def _fake_handle(pid: int = 4242) -> qemu.QemuHandle:
    proc = MagicMock()
    proc.pid = pid
    proc.poll.return_value = 0
    proc.returncode = 0
    return qemu.QemuHandle(
        proc=proc, serial_log_path=Path("/tmp/serial.log"),
        pgid=pid, started_at=0.0,
    )


def _fake_ssh_ok(target, cmd, timeout_s=120.0):
    return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")


class _PatchHostEnv:
    def __enter__(self):
        self._patch = patch.object(hostenv, "detect", return_value=hostenv.HostEnv(
            system="Linux", release="6.10.0", has_kvm=True))
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()


# ---------------------------------------------------------------------------
# qemu.spawn OSError wrap
# ---------------------------------------------------------------------------

class QemuSpawnOSErrorTests(unittest.TestCase):
    def test_popen_oserror_becomes_qemu_launch_error(self):
        with TemporaryDirectory() as td:
            launcher = Path(td) / "launcher.sh"
            launcher.write_text("#!/bin/sh\nexit 0\n")
            launcher.chmod(0o755)
            with patch("subprocess.Popen", side_effect=OSError("permission denied")):
                with self.assertRaises(qemu.QemuLaunchError) as cm:
                    qemu.spawn(launcher, {}, Path(td) / "serial.log")
            self.assertIn("permission denied", str(cm.exception))

    def test_run_cell_finalises_result_on_spawn_oserror(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            launcher = tdp / "launcher.sh"
            launcher.write_text("#!/bin/sh\nexit 0\n")
            launcher.chmod(0o755)
            art = tdp / "art"
            inputs = cell_runner.CellInputs(
                cell_id="oserror_cell",
                profile={"kind": "bughunt"},
                workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
                workload_name="noop",
                launcher=launcher,
                artifact_dir=art,
                ssh_target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                         key_path=Path("/dev/null")),
                kvm_required=False,
            )
            with patch("subprocess.Popen", side_effect=OSError("bash gone")):
                r = cell_runner.run_cell(
                    inputs, host=hostenv.HostEnv(system="Linux", release="6.10", has_kvm=True),
                )
            self.assertEqual(r["verdict"], "harness-error")
            self.assertTrue((art / "result.json").exists())


# ---------------------------------------------------------------------------
# AC-7: --detach-vm
# ---------------------------------------------------------------------------

class CliDetachVmTests(unittest.TestCase):
    def test_detach_vm_prints_pid_and_port_skips_workload_and_result_json(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            args = [
                "run",
                "--workload", "smoke",
                "--kind", "bughunt",
                "--no-kvm",
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/launcher.sh",
                "--runs-root", str(tdp / "runs"),
                "--boot-timeout", "1.0",
                "--ssh-port", "10099",
                "--detach-vm",
            ]
            workload_called = MagicMock()
            with _PatchHostEnv(), \
                 patch.object(qemu, "spawn", return_value=_fake_handle(pid=7777)) as spawn_mock, \
                 patch.object(qemu, "stop", return_value=0) as stop_mock, \
                 patch.object(ssh, "wait_for_ssh", return_value=True), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
                 patch("harness.workloads.by_name", return_value=workload_called), \
                 patch("sys.stdout") as stdout_mock:
                rc = cli.main(args)

            self.assertEqual(rc, cli.KSFT_PASS)
            spawn_mock.assert_called_once()
            stop_mock.assert_not_called()
            workload_called.assert_not_called()

            cell_dirs = list((tdp / "runs").glob("*"))
            self.assertEqual(len(cell_dirs), 1)
            cell_dir = cell_dirs[0]
            self.assertTrue((cell_dir / "cell.json").exists())
            self.assertTrue((cell_dir / "extra-cmdline.txt").exists())
            self.assertTrue((cell_dir / "qemu-cmdline.txt").exists())
            self.assertFalse((cell_dir / "result.json").exists(),
                             "--detach-vm must not finalize result.json")

            stdout_writes = "".join(
                str(c.args[0]) if c.args else ""
                for c in stdout_mock.write.call_args_list
            )
            self.assertIn("pid=7777", stdout_writes)
            self.assertIn("ssh_port=10099", stdout_writes)


# ---------------------------------------------------------------------------
# AC-7: --interactive threads through to qemu.spawn
# ---------------------------------------------------------------------------

class CliInteractiveTests(unittest.TestCase):
    def test_interactive_passes_interactive_true_to_spawn_and_writes_result(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            captured_kwargs = {}

            def _spawn_capturing(launcher, env, serial_log_path, **kwargs):
                captured_kwargs.update(kwargs)
                serial_log_path.parent.mkdir(parents=True, exist_ok=True)
                serial_log_path.write_text("[    0.000] Linux version 6.10\n")
                return _fake_handle()

            args = [
                "run",
                "--workload", "smoke",
                "--kind", "bughunt",
                "--no-kvm",
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/launcher.sh",
                "--runs-root", str(tdp / "runs"),
                "--boot-timeout", "1.0",
                "--interactive",
            ]
            with _PatchHostEnv(), \
                 patch.object(qemu, "spawn", side_effect=_spawn_capturing), \
                 patch.object(qemu, "stop", return_value=0), \
                 patch.object(ssh, "wait_for_ssh", return_value=True), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
                 patch.object(ssh, "fetch_text", return_value=None):
                rc = cli.main(args)
            self.assertEqual(rc, cli.KSFT_PASS)
            self.assertEqual(captured_kwargs.get("interactive"), True)
            cell_dirs = list((tdp / "runs").glob("*"))
            self.assertEqual(len(cell_dirs), 1)
            self.assertTrue((cell_dirs[0] / "result.json").exists(),
                            "--interactive must still write result.json at teardown")


# ---------------------------------------------------------------------------
# workload-fail verdict
# ---------------------------------------------------------------------------

class WorkloadFailVerdictTests(unittest.TestCase):
    def _make_ctx(self, art: Path, workload_name: str):
        inputs = cell_runner.CellInputs(
            cell_id="wf_cell",
            profile={"kind": "bughunt"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name=workload_name),
            workload_name=workload_name,
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                     key_path=Path("/dev/null")),
            kvm_required=False,
        )
        ctx = cell_runner.CellContext(
            cell_id=inputs.cell_id, artifact_dir=art,
            target=inputs.ssh_target, profile=inputs.profile,
        )
        return inputs, ctx

    def _clean_log(self, art: Path):
        (art / "dmesg.log").write_text("[    0.000] Linux version 6.10\n")

    def test_smoke_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "smoke")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "workload-fail")
            self.assertIn("1", out["reason"])

    def test_bench_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "bench")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "workload-fail")

    def test_unixbench_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "unixbench")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 2)
            self.assertEqual(out["verdict"], "workload-fail")

    def test_verify_cleanup_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "verify-cleanup")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "workload-fail")

    def test_lkdtm_nonzero_rc_is_not_workload_fail(self):
        # LKDTM rc!=0 must NOT collapse to workload-fail: the LKDTM helper has
        # its own inversion semantics.
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "lkdtm")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertNotEqual(out["verdict"], "workload-fail")

    def test_kernel_bug_outranks_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "dmesg.log").write_text(
                "[    1.0] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30\n"
            )
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "smoke")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "kernel-bug")


# ---------------------------------------------------------------------------
# AC-6.1: runtime bundle generation
# ---------------------------------------------------------------------------

class RuntimeBundleTests(unittest.TestCase):
    def _kasan_inputs(self, art: Path, store: bundle.BundleStore, cell_id: str = "kasan_cell"):
        inputs = cell_runner.CellInputs(
            cell_id=cell_id,
            profile={"kind": "bughunt"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
            workload_name="noop",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                     key_path=Path("/dev/null")),
            kvm_required=False,
            bundle_store=store,
            kernel_tree=art / "fake_tree",
            kernel_config_path=art / "fake.config",
            rootfs_image=art / "fake.img",
            decode_script=None,
            policy_paths=(),
        )
        ctx = cell_runner.CellContext(
            cell_id=inputs.cell_id, artifact_dir=art,
            target=inputs.ssh_target, profile=inputs.profile,
        )
        return inputs, ctx

    def _kasan_log(self, art: Path, lines_before: int = 80, lines_after: int = 80):
        body = []
        for i in range(lines_before):
            body.append(f"[    0.{i:03d}] padding line {i}")
        body.append("[    1.000] ==================================================================")
        body.append("[    1.001] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30")
        body.append("[    1.002] Read of size 8 at addr ffff8881020100c0 by task lua/1234")
        for i in range(lines_after):
            body.append(f"[    2.{i:03d}] post line {i}")
        (art / "serial.log").write_text("\n".join(body) + "\n")

    def test_kasan_cell_writes_bundle_with_50_line_slice_and_records_in_result(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "cell"
            art.mkdir(parents=True)
            self._kasan_log(art)
            store = bundle.BundleStore()
            inputs, ctx = self._kasan_inputs(art, store)
            r = schemas.empty_result("kasan_cell")
            r["cmdline"] = "lsm=capability,bpf,lua"
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            self.assertEqual(out["verdict"], "kernel-bug")
            self.assertIn("bundle_dir", out)
            self.assertIn("signature_sha1", out)
            self.assertIn("signature_kind", out)
            bd = Path(out["bundle_dir"])
            # Bundles now live inside the cell's own artifact directory.
            self.assertEqual(bd, art / "bundle")
            self.assertTrue(bd.exists())
            for fname in ("kernel.sha", ".config", "config.diff", "cmdline",
                          "commands.sh", "rootfs.sha256", "serial.log",
                          "dmesg.txt", "decoded.txt", "signature"):
                self.assertTrue((bd / fname).exists(),
                                f"bundle missing {fname}")
            self.assertTrue((bd / "policies").is_dir())
            slice_text = (bd / "dmesg.txt").read_text()
            slice_lines = slice_text.splitlines()
            self.assertLessEqual(len(slice_lines), 50,
                                 "dmesg.txt must be at most 50 lines centered on first hit")
            self.assertTrue(
                any("KASAN" in ln for ln in slice_lines),
                "dmesg.txt slice must contain the first KASAN hit",
            )

    def test_duplicate_signature_yields_dup_of_only(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            store = bundle.BundleStore()
            arts: list[Path] = []
            for cid in ("kasan_a", "kasan_b"):
                art = tdp / cid
                art.mkdir(parents=True)
                self._kasan_log(art)
                arts.append(art)
                inputs, ctx = self._kasan_inputs(art, store, cell_id=cid)
                r = schemas.empty_result(cid)
                r["cmdline"] = "lsm=capability,bpf,lua"
                cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            # Each cell now carries its own bundle dir, sibling to its artifacts.
            payload_dir = arts[0] / "bundle"
            dup_dir = arts[1] / "bundle"
            self.assertTrue(payload_dir.is_dir())
            self.assertTrue(dup_dir.is_dir())
            # First share carries the full payload; duplicate carries only the
            # metadata.json + dup_of.txt pointer back to the first bundle.
            self.assertTrue((payload_dir / "serial.log").exists())
            self.assertFalse((dup_dir / "serial.log").exists())
            self.assertTrue((dup_dir / "dup_of.txt").exists())
            self.assertTrue((dup_dir / "metadata.json").exists())
            # dup_of.txt should resolve back to the first-occurrence bundle.
            rel = (dup_dir / "dup_of.txt").read_text().strip()
            self.assertEqual((dup_dir / rel).resolve(), payload_dir.resolve())

    def test_slice_drawn_from_channel_containing_first_hit(self):
        # AC-6.1 channel-correct slice: when serial.log is clean and the splat
        # is only in dmesg.log, the bundle's dmesg.txt slice must come from
        # dmesg.log (the channel with the hit), not from the serial channel.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "cell"
            art.mkdir(parents=True)
            # Serial is clean and noisy -- a per-aggregate-offset slicer would
            # pick the wrong channel and miss the splat entirely.
            serial_lines = [f"[    0.{i:03d}] boot line {i}" for i in range(200)]
            (art / "serial.log").write_text("\n".join(serial_lines) + "\n")
            dmesg_lines = [f"[    1.{i:03d}] post-boot {i}" for i in range(60)]
            dmesg_lines.append(
                "[    2.000] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30"
            )
            dmesg_lines.append(
                "[    2.001] Read of size 8 at addr ffff8881020100c0 by task lua/1234"
            )
            dmesg_lines.extend(
                f"[    3.{i:03d}] trail {i}" for i in range(60)
            )
            (art / "dmesg.log").write_text("\n".join(dmesg_lines) + "\n")
            store = bundle.BundleStore()
            inputs, ctx = self._kasan_inputs(art, store)
            r = schemas.empty_result("kasan_cell")
            r["cmdline"] = "lsm=capability,bpf,lua"
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            self.assertEqual(out["verdict"], "kernel-bug")
            bd = Path(out["bundle_dir"])
            slice_text = (bd / "dmesg.txt").read_text()
            self.assertIn(
                "BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30",
                slice_text,
                "slice must come from the channel that contained the hit",
            )
            # Serial-only boot noise should NOT appear in the slice.
            self.assertNotIn("[    0.050] boot line 50", slice_text)
            slice_lines = slice_text.splitlines()
            self.assertLessEqual(len(slice_lines), 50)

    def test_bundle_records_commands_and_resolved_policies(self):
        # AC-6.1: commands.sh must contain the cell's replay commands; policies
        # passed via policy_paths must be copied into bundle/policies/.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "cell"
            art.mkdir(parents=True)
            self._kasan_log(art)
            pol_src = tdp / "policies_src"
            pol_src.mkdir()
            hello = pol_src / "hello.lua"
            hello.write_text("-- hello policy\n")
            store = bundle.BundleStore()
            inputs = cell_runner.CellInputs(
                cell_id="kasan_cell",
                profile={"kind": "bughunt"},
                workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
                workload_name="noop",
                launcher=Path("/nonexistent/run.sh"),
                artifact_dir=art,
                ssh_target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                         key_path=Path("/dev/null")),
                kvm_required=False,
                bundle_store=store,
                kernel_tree=art / "fake_tree",
                kernel_config_path=art / "fake.config",
                rootfs_image=art / "fake.img",
                decode_script=None,
                policy_paths=(hello,),
            )
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id, artifact_dir=art,
                target=inputs.ssh_target, profile=inputs.profile,
            )
            ctx.commands.append("echo replay-step-1")
            ctx.commands.append("cat /sys/kernel/security/lua/lvm_pool_max")
            r = schemas.empty_result("kasan_cell")
            r["cmdline"] = "lsm=capability,bpf,lua"
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            bd = Path(out["bundle_dir"])
            cmds_text = (bd / "commands.sh").read_text()
            self.assertIn("echo replay-step-1", cmds_text)
            self.assertIn(
                "cat /sys/kernel/security/lua/lvm_pool_max",
                cmds_text,
            )
            self.assertTrue((bd / "policies" / "hello.lua").exists())
            self.assertEqual(
                (bd / "policies" / "hello.lua").read_text(),
                "-- hello policy\n",
            )


# ---------------------------------------------------------------------------
# AC-4: SIGINT QEMU reap
# ---------------------------------------------------------------------------

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

            plan = matrix.MatrixPlan(name="m", cells=[
                matrix.CellSpec(cell_id="cell-a",
                                profile={"workload": "smoke"}, workload="smoke"),
            ])
            opts = matrix.ExecutorOpts(
                parallel=1, runs_root=tdp / "runs",
                matrix_path=None, port_base=20000,
                registry=registry,
            )
            with patch.object(qemu, "stop", return_value=0) as stop_mock:
                matrix.run_matrix(plan, opts, _slow_runner)
            stop_mock.assert_called()
            self.assertTrue(stopped_in_handler and stopped_in_handler[0],
                            "registry.stop_all should have removed cell-a")


# ---------------------------------------------------------------------------
# AC-2.3: kconfig profile validation at planning boundary
# ---------------------------------------------------------------------------

class KconfigValidationTests(unittest.TestCase):
    def test_assert_kconfig_profile_accepts_standard_and_full(self):
        schemas.assert_kconfig_profile("standard")
        schemas.assert_kconfig_profile("full")
        schemas.assert_kconfig_profile(None)

    def test_assert_kconfig_profile_rejects_unknown(self):
        with self.assertRaises(schemas.KconfigProfileError):
            schemas.assert_kconfig_profile("debug")

    def test_run_subcommand_refuses_bad_profile_before_artifact_dir(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            args = [
                "run",
                "--workload", "smoke",
                "--no-kvm",
                "--ssh-key", "/dev/null",
                "--runs-root", str(tdp / "runs"),
                "--kconfig-profile", "bogus",
            ]
            with _PatchHostEnv():
                # argparse rejects choices outside its allowed list.
                with self.assertRaises(SystemExit):
                    cli.main(args)
            self.assertFalse((tdp / "runs").exists(),
                             "no artifact dir should be created on invalid kconfig profile")


# ---------------------------------------------------------------------------
# AC-3.1: LKDTM rc=77 short-circuits BEFORE the no-dmesg early return
# ---------------------------------------------------------------------------

class LkdtmShortCircuitOrderingTests(unittest.TestCase):
    def test_lkdtm_rc77_with_zero_byte_logs_yields_skip_not_no_dmesg(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "serial.log").write_text("")
            (art / "dmesg.log").write_text("")
            inputs = cell_runner.CellInputs(
                cell_id="lkdtm_cell",
                profile={"kind": "bughunt"},
                workload_fn=lambda t, c: cell_runner.WorkloadResult(name="lkdtm"),
                workload_name="lkdtm",
                launcher=Path("/nonexistent/run.sh"),
                artifact_dir=art,
                ssh_target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                         key_path=Path("/dev/null")),
                kvm_required=False,
            )
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id, artifact_dir=art,
                target=inputs.ssh_target, profile=inputs.profile,
            )
            r = schemas.empty_result("lkdtm_cell")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 77)
            self.assertEqual(out["verdict"], "skip:no-lkdtm")


# ---------------------------------------------------------------------------
# AC-2.3: matrix expansion validates every cell's kconfig profile and routes
# --build-kernel through distinct expanded profiles
# ---------------------------------------------------------------------------

class MatrixKconfigValidationTests(unittest.TestCase):
    def _write_matrix(self, td: Path, doc_text: str) -> Path:
        cfg = td / "matrix.json"
        cfg.write_text(doc_text)
        return cfg

    def test_matrix_with_invalid_profile_in_axis_fails_before_runs_dir(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = self._write_matrix(tdp, json.dumps({
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt"},
                "axes": {"kconfig_profile": ["standard", "bogus"]},
            }))
            args = [
                "matrix",
                "--config", str(cfg),
                "--runs-root", str(tdp / "runs"),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
            ]
            with _PatchHostEnv():
                rc = cli.main(args)
            self.assertEqual(rc, cli.KSFT_FAIL,
                             "matrix with bogus kconfig profile must fail at planning")
            self.assertFalse((tdp / "runs").exists(),
                             "runs dir must not be created when a profile is invalid")

    def test_build_kernel_invoked_once_per_distinct_profile(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            # Two cells, two distinct profiles: helper must be called exactly
            # twice with `--kernel <tree> --profile <X>` matching the real
            # enable-debug-kconfig.sh contract (it requires --kernel <dir>).
            cfg = self._write_matrix(tdp, json.dumps({
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt"},
                "axes": {"kconfig_profile": ["standard", "full"]},
            }))
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 0\n")
            helper.chmod(0o755)
            kernel_tree = tdp / "linux"
            kernel_tree.mkdir()

            args = [
                "matrix",
                "--config", str(cfg),
                "--runs-root", str(tdp / "runs"),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
                "--debug-kernel", str(debug_kernel),
                "--kernel-tree", str(kernel_tree),
                "--build-kernel",
                "--parallel", "1",
                # Workload mocks so we never actually try to boot.
            ]

            run_calls: list[list[str]] = []

            def _fake_subprocess_run(cmd, *a, **kw):
                run_calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with _PatchHostEnv(), \
                 patch.object(cli.subprocess, "run", side_effect=_fake_subprocess_run), \
                 patch.object(qemu, "spawn", return_value=_fake_handle()), \
                 patch.object(qemu, "stop", return_value=0), \
                 patch.object(ssh, "wait_for_ssh", return_value=True), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
                 patch("harness.workloads.by_name",
                       return_value=lambda t, c: cell_runner.WorkloadResult(name="smoke")):
                cli.main(args)

            helper_calls = [c for c in run_calls if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(len(helper_calls), 2,
                             f"helper should be invoked once per distinct profile, got {helper_calls!r}")
            # Every helper invocation MUST carry --kernel <tree> AND --profile <X>
            for call in helper_calls:
                self.assertIn("--kernel", call,
                              f"helper call must include --kernel: {call!r}")
                kernel_idx = call.index("--kernel")
                self.assertEqual(call[kernel_idx + 1], str(kernel_tree),
                                 f"--kernel argument should be {kernel_tree}: {call!r}")
                self.assertIn("--profile", call,
                              f"helper call must include --profile: {call!r}")
            seen_profiles = sorted(c[c.index("--profile") + 1] for c in helper_calls)
            self.assertEqual(seen_profiles, ["full", "standard"])

    def test_build_kernel_invoked_once_when_single_distinct_profile(self):
        # When the matrix repeats the same profile across many cells, the
        # helper must still run only once -- and still carry --kernel.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = self._write_matrix(tdp, json.dumps({
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt",
                             "kconfig_profile": "standard"},
                "axes": {"lvm_pool_max": [4, 8, 16]},
            }))
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 0\n")
            helper.chmod(0o755)
            kernel_tree = tdp / "linux"
            kernel_tree.mkdir()
            args = [
                "matrix",
                "--config", str(cfg),
                "--runs-root", str(tdp / "runs"),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
                "--debug-kernel", str(debug_kernel),
                "--kernel-tree", str(kernel_tree),
                "--build-kernel",
            ]
            run_calls: list[list[str]] = []

            def _fake_subprocess_run(cmd, *a, **kw):
                run_calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with _PatchHostEnv(), \
                 patch.object(cli.subprocess, "run", side_effect=_fake_subprocess_run), \
                 patch.object(qemu, "spawn", return_value=_fake_handle()), \
                 patch.object(qemu, "stop", return_value=0), \
                 patch.object(ssh, "wait_for_ssh", return_value=True), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
                 patch("harness.workloads.by_name",
                       return_value=lambda t, c: cell_runner.WorkloadResult(name="smoke")):
                cli.main(args)

            helper_calls = [c for c in run_calls if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(len(helper_calls), 1,
                             f"helper should run exactly once for one distinct profile, got {helper_calls!r}")
            call = helper_calls[0]
            self.assertIn("--kernel", call)
            self.assertEqual(call[call.index("--kernel") + 1], str(kernel_tree))
            self.assertEqual(call[call.index("--profile") + 1], "standard")


# ---------------------------------------------------------------------------
# AC-2.3 (Round 4): --build-kernel enforces the real vendored helper
# contract: --kernel <tree> --profile <X>, and --kernel-tree is required
# and must exist before the helper subprocess runs.
# ---------------------------------------------------------------------------

class BuildKernelRealHelperContractTests(unittest.TestCase):
    def test_build_kernel_requires_kernel_tree(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(json.dumps({
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt",
                             "kconfig_profile": "standard"},
            }))
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 0\n")
            helper.chmod(0o755)

            args = [
                "matrix",
                "--config", str(cfg),
                "--runs-root", str(tdp / "runs"),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
                "--debug-kernel", str(debug_kernel),
                "--build-kernel",
                # Intentionally NO --kernel-tree.
            ]

            called: list[list[str]] = []

            def _record(cmd, *a, **kw):
                called.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with _PatchHostEnv(), \
                 patch.object(cli.subprocess, "run", side_effect=_record):
                rc = cli.main(args)

            self.assertEqual(rc, cli.KSFT_FAIL,
                             "--build-kernel without --kernel-tree must fail at planning")
            self.assertFalse((tdp / "runs").exists(),
                             "runs dir must not be created when --kernel-tree is missing")
            helper_calls = [c for c in called if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(helper_calls, [],
                             "helper must not be invoked when --kernel-tree is missing")

    def test_build_kernel_rejects_nonexistent_kernel_tree(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(json.dumps({
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt",
                             "kconfig_profile": "standard"},
            }))
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 0\n")
            helper.chmod(0o755)
            missing_tree = tdp / "no_such_tree"
            # NOTE: do NOT mkdir; this path must not exist.

            args = [
                "matrix",
                "--config", str(cfg),
                "--runs-root", str(tdp / "runs"),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
                "--debug-kernel", str(debug_kernel),
                "--kernel-tree", str(missing_tree),
                "--build-kernel",
            ]
            called: list[list[str]] = []

            def _record(cmd, *a, **kw):
                called.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with _PatchHostEnv(), \
                 patch.object(cli.subprocess, "run", side_effect=_record):
                rc = cli.main(args)

            self.assertEqual(rc, cli.KSFT_FAIL)
            helper_calls = [c for c in called if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(helper_calls, [],
                             "helper must not be invoked when --kernel-tree path is missing")

    def test_build_kernel_argv_includes_kernel_and_profile_in_order(self):
        # Asserts the EXACT subprocess argv shape: helper, --kernel, <tree>,
        # --profile, <profile>. This is the real helper's required contract.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(json.dumps({
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt",
                             "kconfig_profile": "full"},
            }))
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 0\n")
            helper.chmod(0o755)
            kernel_tree = tdp / "linux"
            kernel_tree.mkdir()

            args = [
                "matrix",
                "--config", str(cfg),
                "--runs-root", str(tdp / "runs"),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
                "--debug-kernel", str(debug_kernel),
                "--kernel-tree", str(kernel_tree),
                "--build-kernel",
            ]
            called: list[list[str]] = []

            def _record(cmd, *a, **kw):
                called.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with _PatchHostEnv(), \
                 patch.object(cli.subprocess, "run", side_effect=_record), \
                 patch.object(qemu, "spawn", return_value=_fake_handle()), \
                 patch.object(qemu, "stop", return_value=0), \
                 patch.object(ssh, "wait_for_ssh", return_value=True), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
                 patch("harness.workloads.by_name",
                       return_value=lambda t, c: cell_runner.WorkloadResult(name="smoke")):
                cli.main(args)

            helper_calls = [c for c in called if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(len(helper_calls), 1)
            expected = [str(helper), "--kernel", str(kernel_tree),
                        "--profile", "full"]
            self.assertEqual(helper_calls[0], expected,
                             f"argv must be exactly {expected!r}, got {helper_calls[0]!r}")

    def test_build_kernel_against_helper_that_requires_kernel(self):
        # Use a fake helper that mimics the real script: rejects missing
        # --kernel with a non-zero exit. With our wiring, the helper now
        # receives --kernel and the run succeeds end-to-end.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(json.dumps({
                "name": "m",
                "defaults": {"workload": "smoke", "kind": "bughunt",
                             "kconfig_profile": "standard"},
            }))
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text(
                "#!/bin/sh\n"
                "saw_kernel=0\n"
                "while [ $# -gt 0 ]; do\n"
                "  case \"$1\" in\n"
                "    --kernel) saw_kernel=1; shift 2 ;;\n"
                "    --profile) shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "if [ \"$saw_kernel\" -ne 1 ]; then\n"
                "  echo 'fake helper: --kernel is required' >&2\n"
                "  exit 1\n"
                "fi\n"
                "exit 0\n"
            )
            helper.chmod(0o755)
            kernel_tree = tdp / "linux"
            kernel_tree.mkdir()

            args = [
                "matrix",
                "--config", str(cfg),
                "--runs-root", str(tdp / "runs"),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
                "--debug-kernel", str(debug_kernel),
                "--kernel-tree", str(kernel_tree),
                "--build-kernel",
            ]
            with _PatchHostEnv(), \
                 patch.object(qemu, "spawn", return_value=_fake_handle()), \
                 patch.object(qemu, "stop", return_value=0), \
                 patch.object(ssh, "wait_for_ssh", return_value=True), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
                 patch("harness.workloads.by_name",
                       return_value=lambda t, c: cell_runner.WorkloadResult(name="smoke")):
                # The real subprocess.run actually executes our fake helper
                # script. If our wiring drops --kernel, the helper exits 1
                # and the matrix planning gate returns KSFT_FAIL.
                rc = cli.main(args)
            self.assertNotEqual(rc, cli.KSFT_FAIL,
                                "helper that requires --kernel must succeed when we pass --kernel")


# ---------------------------------------------------------------------------
# AC-4: SIGINT during a parallel matrix cancels not-yet-started futures so
# the run doesn't sit blocked on cf.as_completed waiting for queued cells.
# ---------------------------------------------------------------------------

class MatrixSigintCancelTests(unittest.TestCase):
    def test_sigint_cancels_queued_cells_and_runs_complete_fast(self):
        import os
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cells = [
                matrix.CellSpec(cell_id=f"c{i}",
                                profile={"kind": "bughunt"},
                                workload="smoke")
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
            self.assertEqual(len(passes), 2,
                             f"exactly two workers were in flight, got {verdicts}")
            self.assertEqual(len(aborts), 6,
                             f"the six queued cells must abort after SIGINT, "
                             f"got {verdicts}")
            # Aborted cells still get a result.json on disk so a triage script
            # can see the full plan.
            runs_subdirs = list((tdp / "runs").iterdir())
            self.assertEqual(len(runs_subdirs), 1,
                             "expected exactly one timestamped runs subdir")
            for cid in aborts:
                self.assertTrue((runs_subdirs[0] / cid / "result.json").exists(),
                                f"missing result.json for aborted cell {cid}")


# ---------------------------------------------------------------------------
# AC-3.3: journalctl-kb.txt is parsed as a tertiary audit-trail channel.
# Hits populate result["journalctl_hits"] but MUST NOT influence verdict --
# verdict belongs to serial.log + dmesg.log alone.
# ---------------------------------------------------------------------------

class JournalctlAuditTrailTests(unittest.TestCase):
    def _inputs(self, art: Path) -> cell_runner.CellInputs:
        return cell_runner.CellInputs(
            cell_id="journal_cell",
            profile={"kind": "bughunt"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="smoke"),
            workload_name="smoke",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(host="127.0.0.1", port=10025, user="root",
                                     key_path=Path("/dev/null")),
            kvm_required=False,
        )

    def test_journalctl_hits_recorded_when_splat_present(self):
        with TemporaryDirectory() as td:
            art = Path(td) / "art"
            art.mkdir()
            (art / "serial.log").write_text("[    0.000] Linux version 6.10\n")
            (art / "dmesg.log").write_text("[    0.001] boot\n")
            (art / "journalctl-kb.txt").write_text(
                "kernel: BUG: KASAN: use-after-free in foo+0x10/0x20\n"
                "kernel: Call Trace:\n"
            )
            inputs = self._inputs(art)
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id, artifact_dir=art,
                target=inputs.ssh_target, profile=inputs.profile,
            )
            r = schemas.empty_result(inputs.cell_id)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)
            # Verdict driven purely by serial+dmesg (no splat there) -> pass.
            self.assertEqual(out["verdict"], "pass",
                             "journalctl hits must not flip verdict to kernel-bug")
            # Audit trail captured the journal-only splat.
            self.assertTrue(out["journalctl_hits"],
                            "journalctl_hits should be populated when journal has splat")
            self.assertTrue(any("KASAN" in h["substring"] for h in out["journalctl_hits"]),
                            f"expected KASAN hit, got {out['journalctl_hits']}")
            # And serial/dmesg classification remained clean.
            self.assertEqual(out["classifier_hits"], [])

    def test_journalctl_hits_empty_when_journal_clean(self):
        with TemporaryDirectory() as td:
            art = Path(td) / "art"
            art.mkdir()
            (art / "serial.log").write_text("[    0.000] Linux version 6.10\n")
            (art / "dmesg.log").write_text("[    0.001] boot\n")
            (art / "journalctl-kb.txt").write_text("kernel: nothing to see here\n")
            inputs = self._inputs(art)
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id, artifact_dir=art,
                target=inputs.ssh_target, profile=inputs.profile,
            )
            r = schemas.empty_result(inputs.cell_id)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)
            self.assertEqual(out["verdict"], "pass")
            self.assertEqual(out["journalctl_hits"], [])

    def test_missing_journalctl_log_is_quiet_no_op(self):
        with TemporaryDirectory() as td:
            art = Path(td) / "art"
            art.mkdir()
            (art / "serial.log").write_text("[    0.000] Linux version 6.10\n")
            (art / "dmesg.log").write_text("[    0.001] boot\n")
            # Deliberately no journalctl-kb.txt -- a teardown without the
            # follower must not raise or pollute result.
            inputs = self._inputs(art)
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id, artifact_dir=art,
                target=inputs.ssh_target, profile=inputs.profile,
            )
            r = schemas.empty_result(inputs.cell_id)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)
            self.assertEqual(out["verdict"], "pass")
            self.assertEqual(out["journalctl_hits"], [])


# ---------------------------------------------------------------------------
# AC-5.1: perf image-warm preflight gates QEMU spawn for perf cells
# ---------------------------------------------------------------------------

class PerfImageWarmPreflightTests(unittest.TestCase):
    def _perf_inputs(self, art: Path, rootfs: Path) -> cell_runner.CellInputs:
        return cell_runner.CellInputs(
            cell_id="perf_cell",
            profile={"kind": "perf"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench"),
            workload_name="bench",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(host="127.0.0.1", port=10024, user="root",
                                     key_path=Path("/dev/null")),
            kvm_required=False,
            rootfs_image=rootfs,
        )

    def test_perf_cell_skips_with_image_not_warm_and_never_spawns(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            # No `<rootfs>.warm-marker` -> preflight must skip.

            def _fail_spawn(*a, **kw):
                raise AssertionError(
                    "qemu.spawn must not be invoked for a cold-rootfs perf cell"
                )

            inputs = self._perf_inputs(art, rootfs)
            with _PatchHostEnv(), patch.object(qemu, "spawn", side_effect=_fail_spawn):
                out = cell_runner.run_cell(inputs)
            self.assertEqual(out["verdict"], "skip:image-not-warm")
            self.assertTrue((art / "result.json").exists())
            # Perf payload must remain the schema's null default (no snapshots
            # were taken) so consumers can distinguish a skipped perf cell from
            # one with measured deltas.
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_cell_proceeds_when_warm_marker_present(self):
        # Marker present -> the preflight gate must NOT short-circuit and
        # qemu.spawn must be reached. We mock the spawn to fail cleanly so we
        # can detect the gate decision without booting a real VM.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            preflight.default_warm_marker(rootfs).write_text("warm\n")
            sentinel = []

            def _spawn_sentinel(*a, **kw):
                sentinel.append(True)
                raise qemu.QemuLaunchError("test-only: stopped before boot")

            inputs = self._perf_inputs(art, rootfs)
            with _PatchHostEnv(), patch.object(qemu, "spawn", side_effect=_spawn_sentinel):
                out = cell_runner.run_cell(inputs)
            self.assertTrue(sentinel, "qemu.spawn must be reached when marker exists")
            # The harness-error verdict comes from the simulated launch failure.
            self.assertEqual(out["verdict"], "harness-error")

    def test_bughunt_cell_ignores_warm_marker(self):
        # Image warmth only gates perf cells; bughunt must NOT skip on a cold
        # rootfs (correctness cells boot a fresh kernel deliberately).
        with TemporaryDirectory() as td:
            tdp = Path(td)
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
                ssh_target=ssh.SshTarget(host="127.0.0.1", port=10025, user="root",
                                         key_path=Path("/dev/null")),
                kvm_required=False,
                rootfs_image=rootfs,
            )
            spawn_calls = []

            def _spawn_count(*a, **kw):
                spawn_calls.append(True)
                raise qemu.QemuLaunchError("test-only")

            with _PatchHostEnv(), patch.object(qemu, "spawn", side_effect=_spawn_count):
                out = cell_runner.run_cell(inputs)
            self.assertTrue(spawn_calls, "bughunt cell must still attempt qemu.spawn")
            self.assertNotEqual(out["verdict"], "skip:image-not-warm")


# ---------------------------------------------------------------------------
# AC-5.1 / AC-9: strict perf both-required (stats AND lsm_funcs)
# ---------------------------------------------------------------------------

class PerfStrictBothRequiredTests(unittest.TestCase):
    def _perf_inputs_warm(self, art: Path, rootfs: Path) -> cell_runner.CellInputs:
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
            ssh_target=ssh.SshTarget(host="127.0.0.1", port=10026, user="root",
                                     key_path=Path("/dev/null")),
            kvm_required=False,
            rootfs_image=rootfs,
        )

    def _run_perf_with_fetch(self, art: Path, rootfs: Path,
                             stats_text: str | None,
                             funcs_text: str | None,
                             workload_invoked: list[bool]) -> dict:
        inputs = self._perf_inputs_warm(art, rootfs)

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

        with _PatchHostEnv(), \
             patch.object(qemu, "spawn", return_value=_fake_handle()), \
             patch.object(qemu, "stop", return_value=0), \
             patch.object(ssh, "wait_for_ssh", return_value=True), \
             patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
             patch.object(cell_runner, "_fetch_perf_texts", side_effect=_fetch_pair):
            return cell_runner.run_cell(inputs)

    def _stats_text(self) -> str:
        # Use the real REQUIRED_COUNTER_KEYS so the strict validator accepts
        # the snapshot. AC-5.1 requires every key in REQUIRED_COUNTER_KEYS to
        # be present before a perf cell is considered measurable.
        lines = [f"{k} = {i}" for i, k in enumerate(schemas.REQUIRED_COUNTER_KEYS)]
        return "\n".join(lines) + "\n"

    def _funcs_text(self) -> str:
        return ("stats for lua-lsm (ns)\n"
                "num name                         nlsm        count           total    average      maxtime\n"
                "----\n"
                "  1 inode_permission             1           5               500      100         200\n")

    def test_perf_skip_when_only_stats_present(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art, rootfs,
                stats_text=self._stats_text(),
                funcs_text=None,
                workload_invoked=workload_invoked,
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(workload_invoked,
                             "workload must not run when perf preflight skips")
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_skip_when_only_lsm_funcs_present(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art, rootfs,
                stats_text=None,
                funcs_text=self._funcs_text(),
                workload_invoked=workload_invoked,
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(workload_invoked)
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_skip_when_both_missing(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art, rootfs,
                stats_text=None,
                funcs_text=None,
                workload_invoked=workload_invoked,
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(workload_invoked)
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_runs_when_both_present(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            (art).mkdir(parents=True, exist_ok=True)
            (art / "dmesg.log").write_text("[    0.000] Linux version 6.10\n")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art, rootfs,
                stats_text=self._stats_text(),
                funcs_text=self._funcs_text(),
                workload_invoked=workload_invoked,
            )
            self.assertTrue(workload_invoked, "workload must run when both files present")
            self.assertNotIn("skip:stats-unavailable", str(out.get("verdict")))
            self.assertIsNotNone(out.get("perf"))


# ---------------------------------------------------------------------------
# Round-4 AC-5.1: perf strict snapshot validates REQUIRED_COUNTER_KEYS and a
# non-empty lsm_funcs table on BOTH the before and after snapshots. A
# malformed-before snapshot must skip before spawning the workload; a
# malformed-after snapshot must finalize the cell as skip:stats-unavailable
# rather than emit a "pass" with partial deltas.
# ---------------------------------------------------------------------------


def _required_counters_text() -> str:
    from harness import schemas as _s
    return "\n".join(f"{k} = {i}" for i, k in enumerate(_s.REQUIRED_COUNTER_KEYS)) + "\n"


def _valid_funcs_text() -> str:
    return ("stats for lua-lsm (ns)\n"
            "num name                         nlsm        count           total    average      maxtime\n"
            "----\n"
            "  1 inode_permission             1           5               500      100         200\n")


class PerfSnapshotValidationTests(unittest.TestCase):
    def test_validate_snapshot_accepts_valid(self):
        from harness import perf_snapshot as ps
        snap = ps.Snapshot()
        snap.counters = ps.parse_stats_text(_required_counters_text())
        snap.lsm_funcs = ps.parse_lsm_funcs_text(_valid_funcs_text())
        self.assertIsNone(ps.validate_snapshot(snap))

    def test_validate_snapshot_rejects_missing_keys(self):
        from harness import perf_snapshot as ps
        snap = ps.Snapshot()
        snap.counters = {"lvm.nalloc": 0}  # only one of the required keys
        snap.lsm_funcs = ps.parse_lsm_funcs_text(_valid_funcs_text())
        reason = ps.validate_snapshot(snap)
        self.assertIsNotNone(reason)
        self.assertIn("missing required counters", reason)

    def test_validate_snapshot_rejects_empty_lsm_funcs(self):
        from harness import perf_snapshot as ps
        snap = ps.Snapshot()
        snap.counters = ps.parse_stats_text(_required_counters_text())
        snap.lsm_funcs = {}
        reason = ps.validate_snapshot(snap)
        self.assertIsNotNone(reason)
        self.assertIn("lsm_funcs", reason)

    def test_validate_snapshot_rejects_none(self):
        from harness import perf_snapshot as ps
        self.assertIsNotNone(ps.validate_snapshot(None))


class PerfStrictValidatesCountersTests(unittest.TestCase):
    """Drive `run_cell` end-to-end with mocked SSH/QEMU and feed it
    intentionally-malformed perf telemetry for either the before-snapshot or
    the after-snapshot. The strict path MUST reject both forms with
    skip:stats-unavailable; the workload MUST NOT see partial-delta passes.
    """

    def _perf_inputs_warm(self, art: Path, rootfs: Path) -> cell_runner.CellInputs:
        preflight.default_warm_marker(rootfs).write_text("warm\n")
        return cell_runner.CellInputs(
            cell_id="perf_cell",
            profile={"kind": "perf"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench", returncode=0),
            workload_name="bench",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(host="127.0.0.1", port=10027, user="root",
                                     key_path=Path("/dev/null")),
            kvm_required=False,
            rootfs_image=rootfs,
        )

    def _run(self, art: Path, rootfs: Path,
             before_pair: tuple[str | None, str | None],
             after_pair: tuple[str | None, str | None]) -> dict:
        inputs = self._perf_inputs_warm(art, rootfs)
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

        with _PatchHostEnv(), \
             patch.object(qemu, "spawn", return_value=_fake_handle()), \
             patch.object(qemu, "stop", return_value=0), \
             patch.object(ssh, "wait_for_ssh", return_value=True), \
             patch.object(ssh, "run", side_effect=_fake_ssh_ok), \
             patch.object(cell_runner, "_fetch_perf_texts", side_effect=_fetch):
            result = cell_runner.run_cell(inputs)
        result["__workload_invoked__"] = bool(workload_invoked)
        return result

    def test_malformed_before_counters_skips_without_workload_spawn(self):
        bad_stats = "lvm.alloc_count = 1\nlvm.alloc_total_ns = 1000\n"  # not REQUIRED keys
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf", tdp / "rootfs.img",
                before_pair=(bad_stats, _valid_funcs_text()),
                after_pair=(_required_counters_text(), _valid_funcs_text()),
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertIn("malformed", out["reason"])
            self.assertFalse(out["__workload_invoked__"],
                             "workload must not run when before-snapshot is malformed")
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_malformed_before_lsm_funcs_skips_without_workload_spawn(self):
        empty_funcs = "stats for lua-lsm (ns)\n"  # header only, no rows
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf", tdp / "rootfs.img",
                before_pair=(_required_counters_text(), empty_funcs),
                after_pair=(_required_counters_text(), _valid_funcs_text()),
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(out["__workload_invoked__"])
            self.assertIsNone(out["perf"].get("snapshots"))

    def test_malformed_after_counters_skips_no_partial_deltas(self):
        bad_stats = "lvm.alloc_count = 1\n"
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf", tdp / "rootfs.img",
                before_pair=(_required_counters_text(), _valid_funcs_text()),
                after_pair=(bad_stats, _valid_funcs_text()),
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable",
                             f"got verdict={out.get('verdict')!r}")
            self.assertTrue(out["__workload_invoked__"],
                            "workload runs when before-snapshot is valid")
            self.assertIn("malformed", out["reason"])
            self.assertIsNone(out["perf"].get("snapshots"),
                              "malformed-after must NOT emit partial-delta snapshots")
            self.assertIsNone(out["perf"].get("deltas"))

    def test_malformed_after_lsm_funcs_skips_no_partial_deltas(self):
        empty_funcs = "stats for lua-lsm (ns)\n"
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf", tdp / "rootfs.img",
                before_pair=(_required_counters_text(), _valid_funcs_text()),
                after_pair=(_required_counters_text(), empty_funcs),
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertTrue(out["__workload_invoked__"])
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_valid_both_sides_produces_full_deltas_and_pass(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf", tdp / "rootfs.img",
                before_pair=(_required_counters_text(), _valid_funcs_text()),
                after_pair=(_required_counters_text(), _valid_funcs_text()),
            )
            self.assertEqual(out["verdict"], "pass",
                             f"got verdict={out.get('verdict')!r}")
            self.assertIsNotNone(out["perf"]["snapshots"])
            self.assertIn("before", out["perf"]["snapshots"])
            self.assertIn("after", out["perf"]["snapshots"])
            self.assertIsNotNone(out["perf"]["deltas"])


# ---------------------------------------------------------------------------
# AC-6.2 (Round 4): bisect-run --cell <profile.yaml|json> single-cell mode
# with KSFT exit map 0 (pass) / 1 (bad) / 125 (untestable) / 128 (abort).
# ---------------------------------------------------------------------------

from harness import bisect as bisect_mod


class BisectRunCellModeTests(unittest.TestCase):
    def _write_cell(self, tdp: Path, profile: dict) -> Path:
        p = tdp / "cell.json"
        p.write_text(json.dumps(profile))
        return p

    def _common_args(self, tdp: Path, cell_path: Path,
                     extra: list[str] | None = None) -> list[str]:
        args = [
            "bisect-run",
            "--cell", str(cell_path),
            "--ssh-key", "/dev/null",
            "--launcher", "/nonexistent/run.sh",
            "--runs-root", str(tdp / "runs"),
            "--port-base", "23000",
        ]
        if extra:
            args.extend(extra)
        return args

    def test_clean_cell_returns_ksft_pass(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {
                "workload": "smoke", "kind": "bughunt",
            })

            def _stub_run_cell(inputs, host=None):
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                result = {
                    "schema_version": 1, "cell_id": inputs.cell_id,
                    "verdict": "pass",
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            with _PatchHostEnv(), \
                 patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(self._common_args(tdp, cell))
            self.assertEqual(rc, bisect_mod.KSFT_PASS)

    def test_classifier_hit_returns_ksft_fail(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {
                "workload": "smoke", "kind": "bughunt",
            })

            def _stub_run_cell(inputs, host=None):
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                result = {
                    "schema_version": 1, "cell_id": inputs.cell_id,
                    "verdict": "kernel-bug",
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            with _PatchHostEnv(), \
                 patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(self._common_args(tdp, cell))
            self.assertEqual(rc, bisect_mod.KSFT_FAIL)

    def test_build_helper_failure_returns_ksft_skip(self):
        # When --build-kernel is set and the helper exits non-zero, the
        # commit cannot be tested. Bisect must skip (125), not fail (1).
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {
                "workload": "smoke", "kind": "bughunt",
                "kconfig_profile": "standard",
            })
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 1\n")
            helper.chmod(0o755)
            kernel_tree = tdp / "linux"
            kernel_tree.mkdir()

            args = self._common_args(tdp, cell, extra=[
                "--debug-kernel", str(debug_kernel),
                "--kernel-tree", str(kernel_tree),
                "--build-kernel",
            ])
            with _PatchHostEnv():
                rc = cli.main(args)
            self.assertEqual(rc, bisect_mod.KSFT_SKIP,
                             "build-helper failure must be bisect-skip (125), not fail")

    def test_image_not_warm_verdict_returns_ksft_skip(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {
                "workload": "bench", "kind": "perf",
            })

            def _stub_run_cell(inputs, host=None):
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                result = {
                    "schema_version": 1, "cell_id": inputs.cell_id,
                    "verdict": "skip:image-not-warm",
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            with _PatchHostEnv(), \
                 patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(self._common_args(tdp, cell))
            self.assertEqual(rc, bisect_mod.KSFT_SKIP)

    def test_build_fail_verdict_returns_ksft_skip(self):
        # build-fail is FAIL_VERDICTS for TAP but UNTESTABLE for bisect.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {
                "workload": "smoke", "kind": "bughunt",
            })

            def _stub_run_cell(inputs, host=None):
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                result = {
                    "schema_version": 1, "cell_id": inputs.cell_id,
                    "verdict": "build-fail",
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            with _PatchHostEnv(), \
                 patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(self._common_args(tdp, cell))
            self.assertEqual(rc, bisect_mod.KSFT_SKIP)

    def test_bundle_write_failure_returns_ksft_abort(self):
        # When the runner finished but bundle emission threw, result["bundle_error"]
        # is set. Bisect must abort (128) so the bisect halts rather than blaming
        # the commit on a harness-side packaging failure.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {
                "workload": "smoke", "kind": "bughunt",
            })

            def _stub_run_cell(inputs, host=None):
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                # The kernel produced a real hit (so the bundle attempt fired)
                # but bundle packaging blew up.
                result = {
                    "schema_version": 1, "cell_id": inputs.cell_id,
                    "verdict": "kernel-bug",
                    "bundle_error": "OSError: disk full",
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            with _PatchHostEnv(), \
                 patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(self._common_args(tdp, cell))
            self.assertEqual(rc, bisect_mod.KSFT_ABORT,
                             "bundle_error must abort bisect (128)")

    def test_run_cell_raises_returns_ksft_abort(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {
                "workload": "smoke", "kind": "bughunt",
            })

            def _stub_run_cell(inputs, host=None):
                raise RuntimeError("harness internal blew up")

            with _PatchHostEnv(), \
                 patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(self._common_args(tdp, cell))
            self.assertEqual(rc, bisect_mod.KSFT_ABORT)

    def test_cell_and_config_are_mutually_exclusive(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cell = self._write_cell(tdp, {"workload": "smoke"})
            mat = tdp / "m.json"
            mat.write_text(json.dumps({"name": "m", "defaults": {"workload": "smoke"}}))
            args = [
                "bisect-run", "--cell", str(cell), "--config", str(mat),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/run.sh",
                "--runs-root", str(tdp / "runs"),
            ]
            with _PatchHostEnv():
                with self.assertRaises(SystemExit) as cm:
                    cli.main(args)
            self.assertNotEqual(cm.exception.code, 0,
                                "argparse must reject --cell with --config")


class BisectExitCodeMappingTests(unittest.TestCase):
    """Pure mapping tests over bisect.exit_code_from_cell_result()."""

    def test_pass(self):
        self.assertEqual(bisect_mod.exit_code_from_cell_result({"verdict": "pass"}),
                         bisect_mod.KSFT_PASS)

    def test_kernel_bug_is_bad(self):
        self.assertEqual(bisect_mod.exit_code_from_cell_result({"verdict": "kernel-bug"}),
                         bisect_mod.KSFT_FAIL)

    def test_workload_fail_is_bad(self):
        self.assertEqual(bisect_mod.exit_code_from_cell_result({"verdict": "workload-fail"}),
                         bisect_mod.KSFT_FAIL)

    def test_build_fail_is_untestable(self):
        self.assertEqual(bisect_mod.exit_code_from_cell_result({"verdict": "build-fail"}),
                         bisect_mod.KSFT_SKIP)

    def test_boot_timeout_is_untestable(self):
        self.assertEqual(bisect_mod.exit_code_from_cell_result({"verdict": "boot-timeout"}),
                         bisect_mod.KSFT_SKIP)

    def test_all_skip_verdicts_are_untestable(self):
        for v in ("skip:no-kvm", "skip:stats-unavailable",
                  "skip:image-not-warm", "skip:no-lkdtm",
                  "skip:fixture-missing"):
            self.assertEqual(bisect_mod.exit_code_from_cell_result({"verdict": v}),
                             bisect_mod.KSFT_SKIP, f"{v} should map to 125")

    def test_harness_error_aborts(self):
        for v in ("harness-error", "aborted", "no-dmesg"):
            self.assertEqual(bisect_mod.exit_code_from_cell_result({"verdict": v}),
                             bisect_mod.KSFT_ABORT, f"{v} should abort")

    def test_bundle_error_aborts_regardless_of_verdict(self):
        self.assertEqual(
            bisect_mod.exit_code_from_cell_result(
                {"verdict": "pass", "bundle_error": "OSError"},
            ),
            bisect_mod.KSFT_ABORT,
        )

    def test_missing_verdict_aborts(self):
        self.assertEqual(bisect_mod.exit_code_from_cell_result({}),
                         bisect_mod.KSFT_ABORT)


if __name__ == "__main__":
    unittest.main()
