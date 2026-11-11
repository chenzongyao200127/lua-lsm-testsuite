"""Contract tests for the --build-kernel helper invocation.

Moved verbatim from tests/test_round2.py: the vendored
enable-debug-kconfig.sh contract (argument shape, exit-code mapping).
"""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from harness import __main__ as cli
from harness import cell_runner, hostenv, qemu, ssh

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


class BuildKernelRealHelperContractTests(unittest.TestCase):
    def test_build_kernel_requires_kernel_tree(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(
                json.dumps(
                    {
                        "name": "m",
                        "defaults": {
                            "workload": "smoke",
                            "kind": "bughunt",
                            "kconfig_profile": "standard",
                        },
                    }
                )
            )
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 0\n")
            helper.chmod(0o755)

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
                "--build-kernel",
                # Intentionally NO --kernel-tree.
            ]

            called: list[list[str]] = []

            def _record(cmd, *a, **kw):
                called.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with _PatchHostEnv(), patch.object(cli.subprocess, "run", side_effect=_record):
                rc = cli.main(args)

            self.assertEqual(
                rc, cli.KSFT_FAIL, "--build-kernel without --kernel-tree must fail at planning"
            )
            self.assertFalse(
                (tdp / "runs").exists(),
                "runs dir must not be created when --kernel-tree is missing",
            )
            helper_calls = [c for c in called if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(
                helper_calls, [], "helper must not be invoked when --kernel-tree is missing"
            )

    def test_build_kernel_rejects_nonexistent_kernel_tree(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(
                json.dumps(
                    {
                        "name": "m",
                        "defaults": {
                            "workload": "smoke",
                            "kind": "bughunt",
                            "kconfig_profile": "standard",
                        },
                    }
                )
            )
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text("#!/bin/sh\nexit 0\n")
            helper.chmod(0o755)
            missing_tree = tdp / "no_such_tree"
            # NOTE: do NOT mkdir; this path must not exist.

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
                str(missing_tree),
                "--build-kernel",
            ]
            called: list[list[str]] = []

            def _record(cmd, *a, **kw):
                called.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with _PatchHostEnv(), patch.object(cli.subprocess, "run", side_effect=_record):
                rc = cli.main(args)

            self.assertEqual(rc, cli.KSFT_FAIL)
            helper_calls = [c for c in called if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(
                helper_calls, [], "helper must not be invoked when --kernel-tree path is missing"
            )

    def test_build_kernel_argv_includes_kernel_and_profile_in_order(self):
        # Asserts the EXACT subprocess argv shape: helper, --kernel, <tree>,
        # --profile, <profile>. This is the real helper's required contract.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(
                json.dumps(
                    {
                        "name": "m",
                        "defaults": {
                            "workload": "smoke",
                            "kind": "bughunt",
                            "kconfig_profile": "full",
                        },
                    }
                )
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
            called: list[list[str]] = []

            def _record(cmd, *a, **kw):
                called.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with (
                _PatchHostEnv(),
                patch.object(cli.subprocess, "run", side_effect=_record),
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

            helper_calls = [c for c in called if str(c[0]).endswith("enable-debug-kconfig.sh")]
            self.assertEqual(len(helper_calls), 1)
            expected = [str(helper), "--kernel", str(kernel_tree), "--profile", "full"]
            self.assertEqual(
                helper_calls[0],
                expected,
                f"argv must be exactly {expected!r}, got {helper_calls[0]!r}",
            )

    def test_build_kernel_against_helper_that_requires_kernel(self):
        # Use a fake helper that mimics the real script: rejects missing
        # --kernel with a non-zero exit. With our wiring, the helper now
        # receives --kernel and the run succeeds end-to-end.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "matrix.json"
            cfg.write_text(
                json.dumps(
                    {
                        "name": "m",
                        "defaults": {
                            "workload": "smoke",
                            "kind": "bughunt",
                            "kconfig_profile": "standard",
                        },
                    }
                )
            )
            debug_kernel = tdp / "tools"
            debug_kernel.mkdir()
            helper = debug_kernel / "enable-debug-kconfig.sh"
            helper.write_text(
                "#!/bin/sh\n"
                "saw_kernel=0\n"
                "while [ $# -gt 0 ]; do\n"
                '  case "$1" in\n'
                "    --kernel) saw_kernel=1; shift 2 ;;\n"
                "    --profile) shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                'if [ "$saw_kernel" -ne 1 ]; then\n'
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
            with (
                _PatchHostEnv(),
                patch.object(qemu, "spawn", return_value=_fake_handle()),
                patch.object(qemu, "stop", return_value=0),
                patch.object(ssh, "wait_for_ssh", return_value=True),
                patch.object(ssh, "run", side_effect=_fake_ssh_ok),
                patch(
                    "harness.workloads.by_name",
                    return_value=lambda t, c: cell_runner.WorkloadResult(name="smoke"),
                ),
            ):
                # The real subprocess.run actually executes our fake helper
                # script. If our wiring drops --kernel, the helper exits 1
                # and the matrix planning gate returns KSFT_FAIL.
                rc = cli.main(args)
            self.assertNotEqual(
                rc,
                cli.KSFT_FAIL,
                "helper that requires --kernel must succeed when we pass --kernel",
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
