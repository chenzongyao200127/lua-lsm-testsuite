import unittest

from harness.signature import build_signature, selftest


class SignatureTests(unittest.TestCase):
    def test_two_traces_with_same_top_frame_dedup(self):
        # Different reporter framing (one has print_address_description+print_report,
        # the other only kasan_report) but the same offending callsite and
        # subsequent 5 frames. Must dedup.
        a = [
            "BUG: KASAN: use-after-free in lua_hook_dispatch+0x80/0x140 [security_lua]",
            "Call Trace:",
            " dump_stack_lvl+0x33/0x50",
            " print_address_description+0x33/0x350",
            " print_report+0xc/0x1f0",
            " kasan_report+0xb1/0xe0",
            " lua_hook_dispatch+0x80/0x140 [security_lua]",
            " security_file_open+0x60/0xb0",
            " do_dentry_open+0x180/0x4c0",
            " path_openat+0x9d0/0xe40",
            " do_filp_open+0xe1/0x1d0",
        ]
        b = [
            "BUG: KASAN: use-after-free in lua_hook_dispatch+0x80/0x140 [security_lua]",
            "Call Trace:",
            " dump_stack_lvl+0x33/0x50",
            " kasan_report+0xb1/0xe0",
            " lua_hook_dispatch+0x80/0x140 [security_lua]",
            " security_file_open+0x60/0xb0",
            " do_dentry_open+0x180/0x4c0",
            " path_openat+0x9d0/0xe40",
            " do_filp_open+0xe1/0x1d0",
        ]
        sig_a = build_signature(a)
        sig_b = build_signature(b)
        self.assertEqual(sig_a.kind, "primary")
        self.assertEqual(sig_a.sha1, sig_b.sha1)
        self.assertEqual(len(sig_a.sha1), 40)

    def test_different_top_frames_diverge(self):
        a = [
            "Call Trace:",
            " lua_hook_dispatch+0x80/0x140",
            " security_file_open+0x60/0xb0",
        ]
        c = [
            "Call Trace:",
            " luaH_set+0x10/0x80",
            " lua_table_assign+0x40/0x90",
        ]
        self.assertNotEqual(build_signature(a).sha1, build_signature(c).sha1)

    def test_fallback_when_no_frames(self):
        sig = build_signature(
            ["watchdog: BUG: soft lockup - CPU#0 stuck for 22s!"],
            pattern_label="soft lockup",
            surrounding_slice=["watchdog: BUG: soft lockup - CPU#0 stuck for 22s!"],
        )
        self.assertEqual(sig.kind, "fallback")
        self.assertEqual(len(sig.sha1), 40)

    def test_builtin_selftest_returns_zero(self):
        self.assertEqual(selftest(), 0)


if __name__ == "__main__":
    unittest.main()
