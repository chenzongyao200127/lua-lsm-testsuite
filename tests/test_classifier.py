import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness.classifier import (
    classify_files,
    classify_text,
    has_any_log,
    verdict_for_hits,
)
from harness.classifier_patterns import PATTERN_VERSION, PATTERNS, selftest


class ClassifierTests(unittest.TestCase):
    def test_kasan_line_is_kernel_bug(self):
        log = "\n".join(
            [
                "[    1.234] systemd[1]: hello",
                "[    2.000] BUG: KASAN: use-after-free in lua_lsm_test+0x18/0x40",
                "[    2.001] Read of size 8 at addr ffff88800a1b2c00",
            ]
        )
        hits = classify_text(log)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].pattern, "BUG: KASAN")
        self.assertEqual(hits[0].line, 2)
        self.assertIn("KASAN", hits[0].substring)
        self.assertEqual(verdict_for_hits(hits), "kernel-bug")

    def test_clean_log_returns_pass(self):
        log = "\n".join(
            [
                "[    0.0] Linux version 6.10.0+",
                "[    1.0] systemd[1]: Reached target multi-user.target",
                "[    2.0] login: ",
            ]
        )
        hits = classify_text(log)
        self.assertEqual(hits, [])
        self.assertEqual(verdict_for_hits(hits), "pass")

    def test_anchored_negative_kasan_in_lua_message(self):
        # The substring "KASAN" appears in a benign LSM message. MUST NOT match.
        log = "lua-lsm: registered KASAN-style xattr policy"
        self.assertEqual(classify_text(log), [])

    def test_anchored_negative_lockdep_in_driver_name(self):
        log = "usbcore: registered new interface driver lockdep-test"
        self.assertEqual(classify_text(log), [])

    def test_warn_on_once_source_text_does_not_match(self):
        # A benign log line that contains the literal source-text
        # `WARN_ON_ONCE(` MUST NOT classify as a kernel bug. Real WARN splats
        # carry a `WARNING: CPU:` or `WARNING: ... at <file>:<line>` header
        # which is what the classifier anchors on.
        log = "[ 12.345] lua-lsm: example uses WARN_ON_ONCE(!ptr) in dispatch path"
        self.assertEqual(classify_text(log), [])

    def test_real_warning_cpu_line_is_kernel_bug(self):
        log = (
            "[ 12.345] WARNING: CPU: 0 PID: 1 at security/lua/lsm.c:1145 "
            "lua_hook_dispatch+0x80/0x140"
        )
        hits = classify_text(log)
        labels = [h.pattern for h in hits]
        self.assertIn("WARNING: CPU:", labels)
        self.assertEqual(verdict_for_hits(hits), "kernel-bug")

    def test_classify_files_handles_missing_paths(self):
        with TemporaryDirectory() as td:
            real = Path(td) / "dmesg.log"
            real.write_text("[ 0 ] BUG: KASAN: oops\n")
            missing = Path(td) / "missing.log"
            hits = classify_files([missing, real])
            self.assertTrue(hits)
            self.assertEqual(hits[0].pattern, "BUG: KASAN")

    def test_has_any_log(self):
        with TemporaryDirectory() as td:
            empty = Path(td) / "e.log"
            empty.write_text("")
            real = Path(td) / "r.log"
            real.write_text("hi\n")
            self.assertTrue(has_any_log([empty, real]))
            self.assertFalse(has_any_log([empty]))

    def test_pattern_version_exposed(self):
        self.assertEqual(PATTERN_VERSION, 2)
        self.assertGreater(len(PATTERNS), 10)

    def test_builtin_selftest_returns_zero(self):
        self.assertEqual(selftest(), 0)


if __name__ == "__main__":
    unittest.main()
