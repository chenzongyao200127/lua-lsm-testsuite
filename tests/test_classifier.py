"""Unit tests for dmesg log classification (harness.classifier)."""

from harness.classifier import classify_files, classify_text
from harness.classifier_patterns import PATTERN_VERSION, PATTERNS, selftest


def test_kasan_line_is_kernel_bug():
    log = "\n".join(
        [
            "[    1.234] systemd[1]: hello",
            "[    2.000] BUG: KASAN: use-after-free in lua_lsm_test+0x18/0x40",
            "[    2.001] Read of size 8 at addr ffff88800a1b2c00",
        ]
    )
    hits = classify_text(log)
    assert len(hits) == 1
    assert hits[0].pattern == "BUG: KASAN"
    assert hits[0].line == 2
    assert "KASAN" in hits[0].substring


def test_clean_log_returns_pass():
    log = "\n".join(
        [
            "[    0.0] Linux version 6.10.0+",
            "[    1.0] systemd[1]: Reached target multi-user.target",
            "[    2.0] login: ",
        ]
    )
    assert classify_text(log) == []


def test_anchored_negative_kasan_in_lua_message():
    # The substring "KASAN" appears in a benign LSM message. MUST NOT match.
    log = "lua-lsm: registered KASAN-style xattr policy"
    assert classify_text(log) == []


def test_anchored_negative_lockdep_in_driver_name():
    log = "usbcore: registered new interface driver lockdep-test"
    assert classify_text(log) == []


def test_warn_on_once_source_text_does_not_match():
    # A benign log line that contains the literal source-text
    # `WARN_ON_ONCE(` MUST NOT classify as a kernel bug. Real WARN splats
    # carry a `WARNING: CPU:` or `WARNING: ... at <file>:<line>` header
    # which is what the classifier anchors on.
    log = "[ 12.345] lua-lsm: example uses WARN_ON_ONCE(!ptr) in dispatch path"
    assert classify_text(log) == []


def test_real_warning_cpu_line_is_kernel_bug():
    log = "[ 12.345] WARNING: CPU: 0 PID: 1 at security/lua/lsm.c:1145 lua_hook_dispatch+0x80/0x140"
    hits = classify_text(log)
    labels = [h.pattern for h in hits]
    assert "WARNING: CPU:" in labels


def test_classify_files_handles_missing_paths(tmp_path):
    real = tmp_path / "dmesg.log"
    real.write_text("[ 0 ] BUG: KASAN: oops\n")
    missing = tmp_path / "missing.log"
    hits = classify_files([missing, real])
    assert hits
    assert hits[0].pattern == "BUG: KASAN"


def test_pattern_version_exposed():
    assert PATTERN_VERSION == 2
    assert len(PATTERNS) > 10


def test_builtin_selftest_returns_zero():
    assert selftest() == 0
