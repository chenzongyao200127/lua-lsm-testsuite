"""Shared pytest fixtures for the harness test suite.

unittest.TestCase classes and pytest-style tests coexist during the
modernization transition (phase 6): the module-aligned files convert
smallest-first, and every converted test should prefer these fixtures --
plus monkeypatch / tmp_path -- over `unittest.mock.patch` stacks and
TemporaryDirectory.

Fixture map:
    fake_qemu_handle  a qemu.QemuHandle around a MagicMock process
    linux_host        forces hostenv.detect (and cell_runner.detect) to
                      report Linux + KVM regardless of the real host
    fake_ssh          an ssh.run recorder returning rc=0
    cell_ctx          a CellContext over tmp_path
    share_dir         a fake 9p workspace with the load-bearing trees
    tmp_cwd           a temporary working directory
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from harness import cell_runner, hostenv, qemu, ssh
from harness.celltypes import CellContext

_LINUX_HOST = hostenv.HostEnv(system="Linux", release="6.10.0", has_kvm=True)


@pytest.fixture
def fake_qemu_handle():
    """Return a factory producing QemuHandles around MagicMock processes."""

    def _make(pid: int = 4242) -> qemu.QemuHandle:
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

    return _make


@pytest.fixture
def linux_host(monkeypatch):
    """Force host detection to Linux+KVM for both planning and cell paths.

    Replaces the ad-hoc _PatchHostEnv context manager: the CLI's planning
    gate reads hostenv.detect while the runner reads cell_runner.detect
    (a re-export of the same function), so both must be patched.
    """
    monkeypatch.setattr(hostenv, "detect", lambda: _LINUX_HOST)
    monkeypatch.setattr(cell_runner, "detect", lambda: _LINUX_HOST)
    return _LINUX_HOST


@pytest.fixture
def fake_ssh(monkeypatch):
    """Patch ssh.run with a recorder that always succeeds.

    The recorder exposes `.calls` as a list of (cmd, timeout_s) tuples and
    `.results` as a queue of SshResults to return in order (empty means
    the default rc=0 "ok" result).
    """
    recorder = MagicMock()
    recorder.calls = []

    def _run(target, cmd, timeout_s=120.0):
        recorder.calls.append((cmd, timeout_s))
        if recorder.results:
            r = recorder.results.pop(0)
            return r
        return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")

    recorder.results = []
    monkeypatch.setattr(ssh, "run", _run)
    return recorder


@pytest.fixture
def cell_ctx(tmp_path):
    """A CellContext over tmp_path with a minimal perf profile."""
    return CellContext(
        cell_id="test-cell",
        artifact_dir=tmp_path,
        target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")),
        profile={"kind": "perf", "lsm": "capability,bpf,lua", "lvm_pool_max": 16},
    )


@pytest.fixture
def share_dir(tmp_path) -> Path:
    """A fake 9p host_share workspace with the load-bearing trees.

    Mirrors what matrix.assert_share_dir requires plus the fixture files
    the workloads' guest-side checks look for (workload lua policies and
    helper scripts).
    """
    tools = tmp_path / "lua-lsm-tools"
    (tools / "examples").mkdir(parents=True)
    (tools / "examples" / "hello.lua").write_text("-- fixture policy\n")
    (tools / "tools").mkdir(parents=True)
    for name in ("bench.lua", "lua_lsm_unixbench.sh", "verify_module_cleanup.sh"):
        (tools / "tools" / name).write_text("#!/bin/sh\n")
    (tmp_path / "kernel" / "linux").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def tmp_cwd(tmp_path, monkeypatch):
    """Run the test with cwd inside a temporary directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path
