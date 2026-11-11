import os
import unittest
from unittest import mock

from harness.hostenv import (
    KVM_PATH_ENV,
    HostEnv,
    UnsupportedHostError,
    assert_supported,
    cell_kvm_check,
    detect,
    kvm_skip_payload,
)


class HostEnvTests(unittest.TestCase):
    def test_detect_real_returns_object(self):
        host = detect()
        self.assertIn(host.system, {"Linux", "Darwin", "Windows", "FreeBSD", "OpenBSD"})

    def test_assert_supported_refuses_darwin(self):
        host = HostEnv(system="Darwin", release="25.3.0", has_kvm=False)
        with self.assertRaises(UnsupportedHostError) as ctx:
            assert_supported(host)
        self.assertIn("macOS is not supported", ctx.exception.message)

    def test_assert_supported_passes_linux(self):
        host = HostEnv(system="Linux", release="6.10.0", has_kvm=True)
        # No exception expected.
        assert_supported(host)

    def test_kvm_skip_payload_shape(self):
        p = kvm_skip_payload()
        self.assertEqual(p["verdict"], "skip:no-kvm")
        self.assertIn("QEMU_ACCEL=tcg", str(p["remediation"]))

    def test_cell_kvm_check_returns_skip_when_required_and_missing(self):
        host = HostEnv(system="Linux", release="6.10.0", has_kvm=False)
        out = cell_kvm_check(host, kvm_required=True)
        self.assertIsNotNone(out)
        self.assertEqual(out["verdict"], "skip:no-kvm")

    def test_cell_kvm_check_returns_none_when_kvm_present(self):
        host = HostEnv(system="Linux", release="6.10.0", has_kvm=True)
        self.assertIsNone(cell_kvm_check(host, kvm_required=True))

    def test_cell_kvm_check_returns_none_when_kvm_not_required(self):
        host = HostEnv(system="Linux", release="6.10.0", has_kvm=False)
        self.assertIsNone(cell_kvm_check(host, kvm_required=False))

    def test_detect_with_overrides(self):
        host = detect(system_override="Linux", kvm_path="/this/path/does/not/exist")
        self.assertEqual(host.system, "Linux")
        self.assertFalse(host.has_kvm)


class KvmPathEnvOverrideTests(unittest.TestCase):
    """The LUA_LSM_TESTSUITE_KVM_PATH env var lets operator scripts (and the
    no-KVM acceptance test) force has_kvm=False from a host that happens to
    have /dev/kvm, without requiring the cell to be marked kvm_required=False.

    Production callers that pass an explicit kvm_path= argument must remain
    deterministic — the env var is consulted only when no explicit argument
    is supplied. This isolation is required so the env var cannot leak into
    normal kernel runs by accident.
    """

    def test_env_override_forces_has_kvm_false_when_path_missing(self):
        with mock.patch.dict(os.environ, {KVM_PATH_ENV: "/nonexistent/kvm/path"}, clear=False):
            host = detect(system_override="Linux")
        self.assertFalse(host.has_kvm)

    def test_env_override_can_point_at_real_path(self):
        # When the env var points at something that does exist, has_kvm
        # follows the override (so operators can also test the positive path).
        with mock.patch.dict(os.environ, {KVM_PATH_ENV: "/dev/null"}, clear=False):
            host = detect(system_override="Linux")
        self.assertTrue(host.has_kvm)

    def test_explicit_kvm_path_wins_over_env_override(self):
        """Production determinism: when caller passes kvm_path=, env is ignored."""
        with mock.patch.dict(os.environ, {KVM_PATH_ENV: "/dev/null"}, clear=False):
            host = detect(system_override="Linux", kvm_path="/nope/not/here")
        self.assertFalse(host.has_kvm)

    def test_no_env_var_uses_default_dev_kvm(self):
        """When neither env nor explicit arg is given, default /dev/kvm wins."""
        env = {k: v for k, v in os.environ.items() if k != KVM_PATH_ENV}
        with mock.patch.dict(os.environ, env, clear=True):
            host = detect(system_override="Linux")
        # has_kvm reflects whether /dev/kvm actually exists on this host;
        # on Darwin it doesn't, on a real Linux KVM box it does. The test
        # asserts only that the lookup path is /dev/kvm by checking the
        # boolean matches a direct os.path.exists check.
        self.assertEqual(host.has_kvm, os.path.exists("/dev/kvm"))


if __name__ == "__main__":
    unittest.main()
