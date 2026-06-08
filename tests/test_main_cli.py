"""Integration tests for `python3 -m harness ...` with QEMU/SSH mocked.

These tests exercise the dispatcher end-to-end: the CLI builds a CellInputs
or MatrixPlan, calls cell_runner.run_cell, the runner spawns a (mocked)
QEMU + waits for SSH + runs a (mocked) workload, and emits result.json /
matrix.json. The tests pin behaviours that Codex's directive plan called
out as load-bearing for AC-1 / AC-7 / AC-6.1.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
from unittest.mock import MagicMock, patch

from harness import __main__ as cli
from harness import bisect, cell_runner, hostenv, matrix, qemu, ssh


def _fake_handle() -> qemu.QemuHandle:
    proc = MagicMock()
    proc.pid = 4242
    proc.poll.return_value = 0
    proc.returncode = 0
    return qemu.QemuHandle(
        proc=proc,
        serial_log_path=Path("/tmp/serial.log"),
        pgid=4242,
        started_at=0.0,
    )


def _fake_ssh_run(target, cmd, timeout_s=120.0):
    """Stand-in for ssh.run that records every command."""
    return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")


class _PatchHostEnv:
    """Force hostenv.detect() to report Linux+KVM regardless of the test host."""

    def __enter__(self):
        self._patch = patch.object(hostenv, "detect", return_value=hostenv.HostEnv(
            system="Linux", release="6.10.0", has_kvm=True))
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()


class CliRunTests(unittest.TestCase):
    def test_run_help_does_not_touch_host(self):
        with self.assertRaises(SystemExit) as cm:
            cli.main(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_run_writes_cell_json_before_boot_attempt(self):
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
            ]
            with _PatchHostEnv(), \
                 patch.object(qemu, "spawn", side_effect=qemu.QemuLaunchError("missing")), \
                 patch.object(ssh, "wait_for_ssh", return_value=False), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_run):
                # KVM not required, so the runner should still spawn (and our
                # mock raises). The cell.json must land regardless.
                rc = cli.main(args)
            self.assertNotEqual(rc, cli.KSFT_PASS)
            cell_dirs = list((tdp / "runs").glob("*"))
            self.assertEqual(len(cell_dirs), 1)
            cell_dir = cell_dirs[0]
            self.assertTrue((cell_dir / "cell.json").exists(),
                            "cell.json must be written before any boot attempt")
            cell_json = json.loads((cell_dir / "cell.json").read_text())
            self.assertEqual(cell_json["workload"], "smoke")

    def test_run_smoke_pass_emits_result_json_with_pass_verdict(self):
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
            ]
            with _PatchHostEnv(), \
                 patch.object(qemu, "spawn", return_value=_fake_handle()), \
                 patch.object(qemu, "stop", return_value=0), \
                 patch.object(ssh, "wait_for_ssh", return_value=True), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_run), \
                 patch.object(ssh, "fetch_text", return_value=None):
                # Make the runner write a serial.log (would normally be QEMU's
                # job) so classifier has *something* to inspect.
                rc_pre = cli.KSFT_PASS  # placeholder
                # Stage a non-empty serial.log into each prospective dir BEFORE
                # the runner starts: simplest is to monkey-patch qemu.spawn
                # to write the log itself.
                def _spawn_with_log(launcher, env, serial_log_path, cwd=None, **kwargs):
                    serial_log_path.parent.mkdir(parents=True, exist_ok=True)
                    serial_log_path.write_text("[    0.000] Linux version 6.10\n")
                    return _fake_handle()

                with patch.object(qemu, "spawn", side_effect=_spawn_with_log):
                    rc = cli.main(args)
            self.assertEqual(rc, cli.KSFT_PASS)
            cell_dirs = list((tdp / "runs").glob("*"))
            self.assertEqual(len(cell_dirs), 1)
            result = json.loads((cell_dirs[0] / "result.json").read_text())
            self.assertEqual(result["verdict"], "pass")
            self.assertGreaterEqual(len(result.get("commands") or []), 1,
                                    "result.json must list the guest commands the workload ran")


class CliMatrixTests(unittest.TestCase):
    def _smoke_config(self) -> Path:
        return Path(__file__).resolve().parent.parent / "configs" / "smoke.json"

    def test_matrix_rejects_share_dir_without_required_entries(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "kernel" / "linux").mkdir(parents=True)
            # lua-lsm-tools is missing -> assert_share_dir refuses.
            with _PatchHostEnv():
                rc = cli.main([
                    "matrix",
                    "--config", str(self._smoke_config()),
                    "--share-dir", str(tdp),
                    "--runs-root", str(tdp / "runs"),
                ])
            self.assertEqual(rc, cli.KSFT_FAIL)

    def test_matrix_dispatches_each_cell_with_distinct_port(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            seen_ports: list[int] = []
            seen_cells: list[str] = []

            def _stub_run_cell(inputs, host=None):
                seen_ports.append(inputs.ssh_target.port)
                seen_cells.append(inputs.cell_id)
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                # Synthesize a minimal pass result so totals aggregate cleanly.
                result = {
                    "schema_version": 1,
                    "cell_id": inputs.cell_id,
                    "verdict": "pass",
                    "started_at": "2026-05-27T00:00:00+00:00",
                    "finished_at": "2026-05-27T00:00:01+00:00",
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            args = [
                "matrix",
                "--config", str(self._smoke_config()),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/launcher.sh",
                "--runs-root", str(tdp / "runs"),
                "--port-base", "11000",
                "--parallel", "1",
            ]
            with _PatchHostEnv(), patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(args)
            self.assertEqual(rc, cli.KSFT_PASS)
            # 32 cells, 32 distinct ports starting at 11000.
            self.assertEqual(len(seen_ports), 32)
            self.assertEqual(len(set(seen_ports)), 32)
            self.assertEqual(min(seen_ports), 11000)
            self.assertEqual(max(seen_ports), 11031)

            # matrix.json was written.
            mj = list((tdp / "runs").rglob("matrix.json"))
            self.assertEqual(len(mj), 1)
            doc = json.loads(mj[0].read_text())
            self.assertEqual(doc["totals"]["passed"], 32)

    def test_bisect_run_returns_ksft_pass_on_all_pass(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)

            def _stub_run_cell(inputs, host=None):
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                result = {
                    "schema_version": 1,
                    "cell_id": inputs.cell_id,
                    "verdict": "pass",
                    "started_at": None,
                    "finished_at": None,
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            args = [
                "bisect-run",
                "--config", str(self._smoke_config()),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/launcher.sh",
                "--runs-root", str(tdp / "runs"),
                "--port-base", "12000",
            ]
            with _PatchHostEnv(), patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(args)
            self.assertEqual(rc, bisect.KSFT_PASS)

    def test_bisect_run_returns_ksft_fail_when_a_cell_fails(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)

            def _stub_run_cell(inputs, host=None):
                inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
                # Force the first cell of the DEC-5 32-cell sweep (sorted axis
                # keys: kconfig_profile, lvm_pool_max, policy, workload) to
                # kernel-bug; the rest pass.
                verdict = "kernel-bug" if "full-0-denyfile-smoke" in inputs.cell_id else "pass"
                result = {
                    "schema_version": 1,
                    "cell_id": inputs.cell_id,
                    "verdict": verdict,
                    "started_at": None,
                    "finished_at": None,
                }
                (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
                return result

            args = [
                "bisect-run",
                "--config", str(self._smoke_config()),
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/launcher.sh",
                "--runs-root", str(tdp / "runs"),
                "--port-base", "13000",
            ]
            with _PatchHostEnv(), patch.object(cell_runner, "run_cell", side_effect=_stub_run_cell):
                rc = cli.main(args)
            self.assertEqual(rc, bisect.KSFT_FAIL)


class CliImageWarmTests(unittest.TestCase):
    def test_image_warm_writes_marker(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            image = tdp / "rootfs.img"
            image.write_text("fake")
            rc = cli.main(["image-warm", "--image", str(image)])
            self.assertEqual(rc, cli.KSFT_PASS)
            marker = image.with_suffix(".img.warm-marker")
            self.assertTrue(marker.exists())

    def test_image_warm_missing_image_returns_fail(self):
        rc = cli.main(["image-warm", "--image", "/nonexistent/rootfs.img"])
        self.assertEqual(rc, cli.KSFT_FAIL)


class CliNoKvmEnvOverrideTests(unittest.TestCase):
    """The LUA_LSM_TESTSUITE_KVM_PATH env var is the supported test hook
    that lets the harness produce a real `skip:no-kvm` verdict on a host
    that happens to have /dev/kvm. The dry-run script's Step 5 uses this
    mechanism to exercise AC-9's no-KVM branch without disabling KVM
    requirement on the cell.
    """

    def test_env_override_produces_skip_no_kvm_without_qemu_spawn(self):
        """End-to-end CLI run: env override + kvm_required=True (default)
        must write verdict=skip:no-kvm to result.json and never spawn QEMU.
        """
        # Capture the real detect() before any patching; we forward to it
        # below to make sure the env var is consulted by the actual
        # production code path, not by the mock framework.
        real_detect = hostenv.detect

        def _detect_linux_honoring_env():
            # Force system=Linux so the planning-time Darwin refusal does
            # not fire on this Darwin test host; everything else (including
            # the env var lookup) flows through the real detect().
            return real_detect(system_override="Linux")

        with TemporaryDirectory() as td:
            tdp = Path(td)
            args = [
                "run",
                "--workload", "smoke",
                "--kind", "bughunt",
                # Deliberately NOT passing --no-kvm: kvm_required stays True,
                # so this exercises the real AC-9 skip:no-kvm branch.
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/launcher.sh",
                "--runs-root", str(tdp / "runs"),
                "--boot-timeout", "1.0",
            ]

            def _fail_if_called(*a, **kw):
                raise AssertionError(
                    "qemu.spawn must NOT be invoked when the env override "
                    "drives the runner into the skip:no-kvm branch"
                )

            env_patch = {hostenv.KVM_PATH_ENV: "/nonexistent/kvm/path"}
            # Patch BOTH the module-level hostenv.detect (used by CLI's
            # _enforce_supported_host) AND the copy imported into
            # cell_runner.run_cell at import time. Both must honor the env
            # var via the real detect() forwarder above.
            with mock.patch.dict(os.environ, env_patch, clear=False), \
                 patch.object(hostenv, "detect", side_effect=_detect_linux_honoring_env), \
                 patch.object(cell_runner, "detect", side_effect=_detect_linux_honoring_env), \
                 patch.object(qemu, "spawn", side_effect=_fail_if_called):
                cli.main(args)

            cell_dirs = list((tdp / "runs").glob("*"))
            self.assertEqual(len(cell_dirs), 1)
            result = json.loads((cell_dirs[0] / "result.json").read_text())
            self.assertEqual(result["verdict"], "skip:no-kvm")
            self.assertIn("/dev/kvm", result.get("reason", ""))

    def test_no_env_override_with_kvm_required_still_attempts_spawn(self):
        """Negative control: with the env override UNSET on a (mocked)
        Linux host that has /dev/kvm, the same CLI args proceed past the
        skip:no-kvm gate and reach qemu.spawn. This proves the env override
        is the ONLY way the env var test affects the verdict; production
        callers without the env var see no behavior change."""
        real_detect = hostenv.detect

        def _detect_linux_with_kvm():
            # Force system=Linux AND kvm_path to something that exists,
            # so cell_runner.run_cell does not short-circuit on skip:no-kvm.
            return real_detect(system_override="Linux", kvm_path="/dev/null")

        with TemporaryDirectory() as td:
            tdp = Path(td)
            args = [
                "run",
                "--workload", "smoke",
                "--kind", "bughunt",
                "--ssh-key", "/dev/null",
                "--launcher", "/nonexistent/launcher.sh",
                "--runs-root", str(tdp / "runs"),
                "--boot-timeout", "1.0",
            ]
            spawn_called = {"v": False}

            def _record_and_fail(*a, **kw):
                spawn_called["v"] = True
                raise qemu.QemuLaunchError("test stop")

            # Ensure the env var is NOT set during this test even if the
            # caller's env happens to define it.
            env_strip = {k: v for k, v in os.environ.items() if k != hostenv.KVM_PATH_ENV}
            with mock.patch.dict(os.environ, env_strip, clear=True), \
                 patch.object(hostenv, "detect", side_effect=_detect_linux_with_kvm), \
                 patch.object(cell_runner, "detect", side_effect=_detect_linux_with_kvm), \
                 patch.object(qemu, "spawn", side_effect=_record_and_fail), \
                 patch.object(ssh, "wait_for_ssh", return_value=False), \
                 patch.object(ssh, "run", side_effect=_fake_ssh_run):
                cli.main(args)
            self.assertTrue(spawn_called["v"],
                            "without env override + with KVM present, the runner must reach qemu.spawn")


class CliHostRefusalTests(unittest.TestCase):
    def test_run_refuses_darwin_at_planning_time(self):
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
            ]
            with patch.object(hostenv, "detect", return_value=hostenv.HostEnv(
                    system="Darwin", release="25.3.0", has_kvm=False)):
                with self.assertRaises(hostenv.UnsupportedHostError):
                    cli.main(args)


if __name__ == "__main__":
    unittest.main()
