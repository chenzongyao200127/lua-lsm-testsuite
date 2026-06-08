import unittest

from harness.cmdline import (
    BUGHUNT_KNOBS,
    CmdlineError,
    compose,
    compose_env,
)


class ComposeTests(unittest.TestCase):
    def test_perf_profile_emits_lsm_and_pool(self):
        profile = {
            "kind": "perf",
            "lsm": "capability,yama,lua,selinux,bpf,integrity",
            "lvm_pool_max": 64,
        }
        cmdline = compose(profile)
        self.assertIn("lsm=capability,yama,lua,selinux,bpf,integrity", cmdline)
        self.assertIn("lua.lvm_pool_max=64", cmdline)
        for knob in BUGHUNT_KNOBS:
            self.assertNotIn(knob, cmdline)

    def test_perf_profile_omits_pool_when_unset(self):
        profile = {"kind": "perf", "lsm": "capability,lua"}
        cmdline = compose(profile)
        self.assertNotIn("lua.lvm_pool_max=", cmdline)

    def test_bughunt_profile_emits_panic_knobs(self):
        profile = {"kind": "bughunt", "lsm": "lua"}
        cmdline = compose(profile)
        for knob in BUGHUNT_KNOBS:
            self.assertIn(knob, cmdline)

    def test_perf_with_injected_panic_knob_is_rejected(self):
        profile = {"kind": "perf", "extra": ["panic_on_warn=1"]}
        with self.assertRaises(CmdlineError):
            compose(profile)

    def test_invalid_kind_rejected(self):
        with self.assertRaises(CmdlineError):
            compose({"kind": "weird"})

    def test_negative_pool_rejected(self):
        with self.assertRaises(CmdlineError):
            compose({"kind": "perf", "lvm_pool_max": -1})

    def test_nodebug_flag(self):
        profile = {"kind": "perf", "nodebug": True}
        self.assertIn("lua.nodebug", compose(profile))

    def test_compose_env_preserves_base_env(self):
        base = {"PATH": "/usr/bin", "HOST_SSH_PORT": "10024"}
        env = compose_env({"kind": "perf", "lsm": "lua"}, base)
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["HOST_SSH_PORT"], "10024")
        self.assertIn("lsm=lua", env["EXTRA_CMDLINE"])


if __name__ == "__main__":
    unittest.main()
