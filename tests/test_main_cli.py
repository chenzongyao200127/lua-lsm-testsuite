"""Integration tests for `python3 -m harness ...` with QEMU/SSH mocked.

These tests exercise the dispatcher end-to-end: the CLI builds a CellInputs
or MatrixPlan, calls cell_runner.run_cell, the runner spawns a (mocked)
QEMU + waits for SSH + runs a (mocked) workload, and emits result.json /
matrix.json. The tests pin behaviours that Codex's directive plan called
out as load-bearing for AC-1 / AC-7 / AC-6.1.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from harness import __main__ as cli
from harness import bisect, cell_runner, hostenv, ksft, qemu, schemas, ssh


def _fake_ssh_run(target, cmd, timeout_s=120.0):
    """Stand-in for ssh.run that records every command."""
    return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")


def _smoke_config() -> Path:
    return Path(__file__).resolve().parent.parent / "configs" / "smoke.json"


def test_functional_policy_resolves_to_repository_fixture(tmp_path):
    paths = cli._resolve_policy_paths(tmp_path, "smoke", "functional")
    assert paths == (tmp_path / "lua-lsm-testsuite" / "fixtures" / "policies" / "smoke.lua",)


def test_artifact_guest_relpath_prefers_share_dir_root(tmp_path):
    workspace = tmp_path
    repo = workspace / "lua-lsm-testsuite"
    artifact = repo / "runs" / "cell-1"
    artifact.mkdir(parents=True)
    rel = cell_runner.derive_guest_relpath(
        artifact,
        workspace_root=repo,
        override=None,
        share_dir=workspace,
    )
    assert rel == "lua-lsm-testsuite/runs/cell-1"


def test_artifact_guest_relpath_falls_back_to_workspace_root(tmp_path):
    repo = tmp_path
    artifact = repo / "runs" / "cell-1"
    artifact.mkdir(parents=True)
    rel = cell_runner.derive_guest_relpath(
        artifact,
        workspace_root=repo,
        override=None,
        share_dir=None,
    )
    assert rel == "runs/cell-1"


def test_run_help_does_not_touch_host():
    with pytest.raises(SystemExit) as ctx:
        cli.main(["--help"])
    assert ctx.value.code == 0


def test_run_writes_cell_json_before_boot_attempt(tmp_path, linux_host, monkeypatch):
    args = [
        "run",
        "--workload",
        "smoke",
        "--kind",
        "bughunt",
        "--no-kvm",
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
        "--boot-timeout",
        "1.0",
    ]

    def _boom(*_a, **_kw):
        raise qemu.QemuLaunchError("missing")

    monkeypatch.setattr(qemu, "spawn", _boom)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: False)
    monkeypatch.setattr(ssh, "run", _fake_ssh_run)
    # KVM not required, so the runner should still spawn (and our
    # mock raises). The cell.json must land regardless.
    rc = cli.main(args)
    assert rc != ksft.KSFT_PASS
    cell_dirs = list((tmp_path / "runs").glob("*"))
    assert len(cell_dirs) == 1
    cell_dir = cell_dirs[0]
    assert (cell_dir / "cell.json").exists(), "cell.json must be written before any boot attempt"
    cell_json = json.loads((cell_dir / "cell.json").read_text())
    assert cell_json["workload"] == "smoke"


def test_run_smoke_pass_emits_result_json_with_pass_verdict(
    tmp_path, linux_host, monkeypatch, fake_qemu_handle
):
    args = [
        "run",
        "--workload",
        "smoke",
        "--kind",
        "bughunt",
        "--no-kvm",
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
        "--boot-timeout",
        "1.0",
    ]
    monkeypatch.setattr(qemu, "stop", lambda *a, **kw: 0)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: True)
    monkeypatch.setattr(ssh, "run", _fake_ssh_run)
    monkeypatch.setattr(ssh, "fetch_text", lambda *a, **kw: None)

    # Make the runner write a serial.log (would normally be QEMU's job) so
    # the classifier has *something* to inspect: qemu.spawn writes the log.
    def _spawn_with_log(launcher, env, serial_log_path, cwd=None, **kwargs):
        serial_log_path.parent.mkdir(parents=True, exist_ok=True)
        serial_log_path.write_text("[    0.000] Linux version 6.10\n")
        return fake_qemu_handle()

    monkeypatch.setattr(qemu, "spawn", _spawn_with_log)
    rc = cli.main(args)
    assert rc == ksft.KSFT_PASS
    cell_dirs = list((tmp_path / "runs").glob("*"))
    assert len(cell_dirs) == 1
    result = json.loads((cell_dirs[0] / "result.json").read_text())
    assert result["verdict"] == "pass"
    assert len(result.get("commands") or []) >= 1, (
        "result.json must list the guest commands the workload ran"
    )


def test_matrix_rejects_share_dir_without_required_entries(tmp_path, linux_host):
    (tmp_path / "kernel" / "linux").mkdir(parents=True)
    # lua-lsm-tools is missing -> assert_share_dir refuses.
    rc = cli.main(
        [
            "matrix",
            "--config",
            str(_smoke_config()),
            "--share-dir",
            str(tmp_path),
            "--runs-root",
            str(tmp_path / "runs"),
        ]
    )
    assert rc == ksft.KSFT_FAIL


def _pass_result_stub(inputs, host=None):
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


def test_matrix_dispatches_each_cell_with_distinct_port(tmp_path, linux_host, monkeypatch):
    seen_ports: list[int] = []
    seen_cells: list[str] = []

    def _stub_run_cell(inputs, host=None):
        seen_ports.append(inputs.ssh_target.port)
        seen_cells.append(inputs.cell_id)
        return _pass_result_stub(inputs, host=host)

    args = [
        "matrix",
        "--config",
        str(_smoke_config()),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
        "--port-base",
        "11000",
        "--parallel",
        "1",
    ]
    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    rc = cli.main(args)
    assert rc == ksft.KSFT_PASS
    # 32 cells, 32 distinct ports starting at 11000.
    assert len(seen_ports) == 32
    assert len(set(seen_ports)) == 32
    assert min(seen_ports) == 11000
    assert max(seen_ports) == 11031

    # matrix.json was written.
    mj = list((tmp_path / "runs").rglob("matrix.json"))
    assert len(mj) == 1
    doc = json.loads(mj[0].read_text())
    assert doc["totals"]["passed"] == 32


def test_bisect_run_returns_ksft_pass_on_all_pass(tmp_path, linux_host, monkeypatch):
    monkeypatch.setattr(cell_runner, "run_cell", _pass_result_stub)
    args = [
        "bisect-run",
        "--config",
        str(_smoke_config()),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
        "--port-base",
        "12000",
    ]
    rc = cli.main(args)
    assert rc == bisect.KSFT_PASS


def test_bisect_run_returns_ksft_fail_when_a_cell_fails(tmp_path, linux_host, monkeypatch):
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

    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    args = [
        "bisect-run",
        "--config",
        str(_smoke_config()),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
        "--port-base",
        "13000",
    ]
    rc = cli.main(args)
    assert rc == bisect.KSFT_FAIL


def test_image_warm_writes_marker(tmp_path):
    image = tmp_path / "rootfs.img"
    image.write_text("fake")
    rc = cli.main(["image-warm", "--image", str(image)])
    assert rc == ksft.KSFT_PASS
    marker = image.with_suffix(".img.warm-marker")
    assert marker.exists()


def test_image_warm_missing_image_returns_fail():
    rc = cli.main(["image-warm", "--image", "/nonexistent/rootfs.img"])
    assert rc == ksft.KSFT_FAIL


class TestCliNoKvmEnvOverride:
    """The LUA_LSM_TESTSUITE_KVM_PATH env var is the supported test hook
    that lets the harness produce a real `skip:no-kvm` verdict on a host
    that happens to have /dev/kvm. The dry-run script's Step 5 uses this
    mechanism to exercise AC-9's no-KVM branch without disabling KVM
    requirement on the cell.
    """

    def test_env_override_produces_skip_no_kvm_without_qemu_spawn(self, tmp_path, monkeypatch):
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

        args = [
            "run",
            "--workload",
            "smoke",
            "--kind",
            "bughunt",
            # Deliberately NOT passing --no-kvm: kvm_required stays True,
            # so this exercises the real AC-9 skip:no-kvm branch.
            "--ssh-key",
            "/dev/null",
            "--launcher",
            "/nonexistent/launcher.sh",
            "--runs-root",
            str(tmp_path / "runs"),
            "--boot-timeout",
            "1.0",
        ]

        def _fail_if_called(*a, **kw):
            raise AssertionError(
                "qemu.spawn must NOT be invoked when the env override "
                "drives the runner into the skip:no-kvm branch"
            )

        monkeypatch.setenv(hostenv.KVM_PATH_ENV, "/nonexistent/kvm/path")
        # Patch BOTH the module-level hostenv.detect (used by CLI's
        # _enforce_supported_host) AND the copy imported into
        # cell_runner.run_cell at import time. Both must honor the env
        # var via the real detect() forwarder above.
        monkeypatch.setattr(hostenv, "detect", _detect_linux_honoring_env)
        monkeypatch.setattr(cell_runner, "detect", _detect_linux_honoring_env)
        monkeypatch.setattr(qemu, "spawn", _fail_if_called)
        cli.main(args)

        cell_dirs = list((tmp_path / "runs").glob("*"))
        assert len(cell_dirs) == 1
        result = json.loads((cell_dirs[0] / "result.json").read_text())
        assert result["verdict"] == "skip:no-kvm"
        assert "/dev/kvm" in result.get("reason", "")

    def test_no_env_override_with_kvm_required_still_attempts_spawn(self, tmp_path, monkeypatch):
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

        args = [
            "run",
            "--workload",
            "smoke",
            "--kind",
            "bughunt",
            "--ssh-key",
            "/dev/null",
            "--launcher",
            "/nonexistent/launcher.sh",
            "--runs-root",
            str(tmp_path / "runs"),
            "--boot-timeout",
            "1.0",
        ]
        spawn_called = {"v": False}

        def _record_and_fail(*a, **kw):
            spawn_called["v"] = True
            raise qemu.QemuLaunchError("test stop")

        # Ensure the env var is NOT set during this test even if the
        # caller's env happens to define it.
        monkeypatch.delenv(hostenv.KVM_PATH_ENV, raising=False)
        monkeypatch.setattr(hostenv, "detect", _detect_linux_with_kvm)
        monkeypatch.setattr(cell_runner, "detect", _detect_linux_with_kvm)
        monkeypatch.setattr(qemu, "spawn", _record_and_fail)
        monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: False)
        monkeypatch.setattr(ssh, "run", _fake_ssh_run)
        cli.main(args)
        assert spawn_called["v"], (
            "without env override + with KVM present, the runner must reach qemu.spawn"
        )


def test_run_refuses_darwin_at_planning_time(tmp_path, monkeypatch):
    args = [
        "run",
        "--workload",
        "smoke",
        "--kind",
        "bughunt",
        "--no-kvm",
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
    ]
    monkeypatch.setattr(
        hostenv,
        "detect",
        lambda: hostenv.HostEnv(system="Darwin", release="25.3.0", has_kvm=False),
    )
    with pytest.raises(hostenv.UnsupportedHostError):
        cli.main(args)


# ---------------------------------------------------------------------------
# Moved from tests/test_round2.py (round-2 dissolution), now pytest-style.
# ---------------------------------------------------------------------------


def test_detach_vm_prints_pid_and_port_skips_workload_and_result_json(
    tmp_path, linux_host, monkeypatch, fake_qemu_handle, capsys
):
    args = [
        "run",
        "--workload",
        "smoke",
        "--kind",
        "bughunt",
        "--no-kvm",
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
        "--boot-timeout",
        "1.0",
        "--ssh-port",
        "10099",
        "--detach-vm",
    ]
    workload_called = MagicMock()
    spawn_mock = MagicMock(return_value=fake_qemu_handle(pid=7777))
    stop_mock = MagicMock(return_value=0)
    monkeypatch.setattr(qemu, "spawn", spawn_mock)
    monkeypatch.setattr(qemu, "stop", stop_mock)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: True)
    monkeypatch.setattr(ssh, "run", _fake_ssh_run)
    monkeypatch.setattr("harness.workloads.by_name", lambda _name: workload_called)
    rc = cli.main(args)

    assert rc == ksft.KSFT_PASS
    spawn_mock.assert_called_once()
    stop_mock.assert_not_called()
    workload_called.assert_not_called()

    cell_dirs = list((tmp_path / "runs").glob("*"))
    assert len(cell_dirs) == 1
    cell_dir = cell_dirs[0]
    assert (cell_dir / "cell.json").exists()
    assert (cell_dir / "extra-cmdline.txt").exists()
    assert (cell_dir / "qemu-cmdline.txt").exists()
    assert not (cell_dir / "result.json").exists(), "--detach-vm must not finalize result.json"

    stdout_writes = capsys.readouterr().out
    assert "pid=7777" in stdout_writes
    assert "ssh_port=10099" in stdout_writes


def test_interactive_passes_interactive_true_to_spawn_and_writes_result(
    tmp_path, linux_host, monkeypatch, fake_qemu_handle
):
    captured_kwargs = {}

    def _spawn_capturing(launcher, env, serial_log_path, **kwargs):
        captured_kwargs.update(kwargs)
        serial_log_path.parent.mkdir(parents=True, exist_ok=True)
        serial_log_path.write_text("[    0.000] Linux version 6.10\n")
        return fake_qemu_handle()

    args = [
        "run",
        "--workload",
        "smoke",
        "--kind",
        "bughunt",
        "--no-kvm",
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/launcher.sh",
        "--runs-root",
        str(tmp_path / "runs"),
        "--boot-timeout",
        "1.0",
        "--interactive",
    ]
    monkeypatch.setattr(qemu, "spawn", _spawn_capturing)
    monkeypatch.setattr(qemu, "stop", lambda *a, **kw: 0)
    monkeypatch.setattr(ssh, "wait_for_ssh", lambda *a, **kw: True)
    monkeypatch.setattr(ssh, "run", _fake_ssh_run)
    monkeypatch.setattr(ssh, "fetch_text", lambda *a, **kw: None)
    rc = cli.main(args)
    assert rc == ksft.KSFT_PASS
    assert captured_kwargs.get("interactive") is True
    cell_dirs = list((tmp_path / "runs").glob("*"))
    assert len(cell_dirs) == 1
    assert (cell_dirs[0] / "result.json").exists(), (
        "--interactive must still write result.json at teardown"
    )


@pytest.mark.parametrize("profile", ["standard", "full", None])
def test_assert_kconfig_profile_accepts_known_profiles(profile):
    schemas.assert_kconfig_profile(profile)


def test_assert_kconfig_profile_rejects_unknown():
    with pytest.raises(schemas.KconfigProfileError):
        schemas.assert_kconfig_profile("debug")


def test_run_subcommand_refuses_bad_profile_before_artifact_dir(tmp_path, linux_host):
    args = [
        "run",
        "--workload",
        "smoke",
        "--no-kvm",
        "--ssh-key",
        "/dev/null",
        "--runs-root",
        str(tmp_path / "runs"),
        "--kconfig-profile",
        "bogus",
    ]
    with pytest.raises(SystemExit):
        # argparse rejects choices outside its allowed list.
        cli.main(args)
    assert not (tmp_path / "runs").exists(), (
        "no artifact dir should be created on invalid kconfig profile"
    )
