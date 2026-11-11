"""Unit tests for host environment detection and KVM gating (harness.hostenv)."""

import os

import pytest
from harness import hostenv
from harness.hostenv import (
    KVM_PATH_ENV,
    HostEnv,
    UnsupportedHostError,
    assert_supported,
    cell_kvm_check,
    detect,
    kvm_skip_payload,
)


def test_detect_real_returns_object(monkeypatch):
    # Pin the platform probes so the test does not depend on the host it
    # runs on; the KVM lookup still follows the real env/default path.
    monkeypatch.setattr(hostenv.platform, "system", lambda: "Linux")
    monkeypatch.setattr(hostenv.platform, "release", lambda: "6.10.0-test")
    monkeypatch.delenv(KVM_PATH_ENV, raising=False)
    host = detect()
    assert host.system == "Linux"
    assert host.release == "6.10.0-test"
    assert host.has_kvm == os.path.exists("/dev/kvm")


def test_assert_supported_refuses_darwin():
    host = HostEnv(system="Darwin", release="25.3.0", has_kvm=False)
    with pytest.raises(UnsupportedHostError) as ctx:
        assert_supported(host)
    assert "macOS is not supported" in ctx.value.message


def test_assert_supported_passes_linux():
    host = HostEnv(system="Linux", release="6.10.0", has_kvm=True)
    # No exception expected.
    assert_supported(host)


def test_kvm_skip_payload_shape():
    p = kvm_skip_payload()
    assert p["verdict"] == "skip:no-kvm"
    assert "QEMU_ACCEL=tcg" in str(p["remediation"])


def test_cell_kvm_check_returns_skip_when_required_and_missing():
    host = HostEnv(system="Linux", release="6.10.0", has_kvm=False)
    out = cell_kvm_check(host, kvm_required=True)
    assert out is not None
    assert out["verdict"] == "skip:no-kvm"


def test_cell_kvm_check_returns_none_when_kvm_present():
    host = HostEnv(system="Linux", release="6.10.0", has_kvm=True)
    assert cell_kvm_check(host, kvm_required=True) is None


def test_cell_kvm_check_returns_none_when_kvm_not_required():
    host = HostEnv(system="Linux", release="6.10.0", has_kvm=False)
    assert cell_kvm_check(host, kvm_required=False) is None


def test_detect_with_overrides():
    host = detect(system_override="Linux", kvm_path="/this/path/does/not/exist")
    assert host.system == "Linux"
    assert not host.has_kvm


class TestKvmPathEnvOverride:
    """The LUA_LSM_TESTSUITE_KVM_PATH env var lets operator scripts (and the
    no-KVM acceptance test) force has_kvm=False from a host that happens to
    have /dev/kvm, without requiring the cell to be marked kvm_required=False.

    Production callers that pass an explicit kvm_path= argument must remain
    deterministic — the env var is consulted only when no explicit argument
    is supplied. This isolation is required so the env var cannot leak into
    normal kernel runs by accident.
    """

    def test_env_override_forces_has_kvm_false_when_path_missing(self, monkeypatch):
        monkeypatch.setenv(KVM_PATH_ENV, "/nonexistent/kvm/path")
        host = detect(system_override="Linux")
        assert not host.has_kvm

    def test_env_override_can_point_at_real_path(self, monkeypatch):
        # When the env var points at something that does exist, has_kvm
        # follows the override (so operators can also test the positive path).
        monkeypatch.setenv(KVM_PATH_ENV, "/dev/null")
        host = detect(system_override="Linux")
        assert host.has_kvm

    def test_explicit_kvm_path_wins_over_env_override(self, monkeypatch):
        """Production determinism: when caller passes kvm_path=, env is ignored."""
        monkeypatch.setenv(KVM_PATH_ENV, "/dev/null")
        host = detect(system_override="Linux", kvm_path="/nope/not/here")
        assert not host.has_kvm

    def test_no_env_var_uses_default_dev_kvm(self, monkeypatch):
        """When neither env nor explicit arg is given, default /dev/kvm wins."""
        monkeypatch.delenv(KVM_PATH_ENV, raising=False)
        host = detect(system_override="Linux")
        # has_kvm reflects whether /dev/kvm actually exists on this host;
        # the test asserts only that the lookup path is /dev/kvm by checking
        # the boolean matches a direct os.path.exists check.
        assert host.has_kvm == os.path.exists("/dev/kvm")
