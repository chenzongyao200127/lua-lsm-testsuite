"""Unit tests for dmesg log classification (harness.classifier)."""

from harness.classifier import classify_files, classify_text, split_ignored
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


def test_split_ignored_baselines_matching_header_only():
    log = "\n".join(
        [
            "[    7.4] BUG: KCSAN: data-race in folio_batch_move_lru / next_uptodate_folio",
            "[    9.0] BUG: KASAN: use-after-free in lua_module_unregister+0x18/0x40",
        ]
    )
    hits = classify_text(log)
    fatal, ignored = split_ignored(hits, [r"BUG: KCSAN: data-race in folio_batch_move_lru"])
    assert [h.pattern for h in ignored] == ["BUG: KCSAN"]
    assert [h.pattern for h in fatal] == ["BUG: KASAN"]
    # The full line is preserved so baselines can anchor past the label.
    assert ignored[0].text.startswith("[    7.4] BUG: KCSAN: data-race in")


def test_split_ignored_without_baselines_keeps_everything():
    hits = classify_text("BUG: KCSAN: data-race in a / b\n")
    fatal, ignored = split_ignored(hits, ())
    assert fatal == hits
    assert ignored == []


KCSAN_LUA_RULE = (
    r"(?s)BUG: KCSAN: data-race in "
    r"(?!.*(?:lua_lsm|luaV_|lvm|kvcache|shdict|module_load|Arith|l_strcmp|traceexec))"
)


def _kcsan_report(header, frames):
    return "\n".join(
        [
            "[    1.0] ==================================================================",
            f"[    1.0] BUG: KCSAN: data-race in {header}",
            "[    1.0] ",
            "[    1.0] write to 0xffff888000000000 of 8 bytes by task 10 on cpu 0:",
            *[f"[    1.0]  {f}" for f in frames],
            "[    1.0] ==================================================================",
        ]
    )


def test_block_rule_ignores_report_with_only_upstream_frames():
    log = _kcsan_report("__fput / kernfs_refresh_inode", ["__fput+0x1/0x2", "task_work_run+0x3/0x4"])
    fatal, ignored = split_ignored(classify_text(log), (), [KCSAN_LUA_RULE])
    assert [h.pattern for h in ignored] == ["BUG: KCSAN"]
    assert fatal == []


def test_block_rule_sees_lua_frame_below_a_noise_header():
    # The header names only upstream symbols; the raced access came from the
    # interpreter, which only the stack frames reveal.
    log = _kcsan_report("folio_batch_move_lru / next_uptodate_folio",
                        ["next_uptodate_folio+0x1/0x2", "luaV_execute+0x3/0x4"])
    fatal, ignored = split_ignored(classify_text(log), (), [KCSAN_LUA_RULE])
    assert ignored == []
    assert [h.pattern for h in fatal] == ["BUG: KCSAN"]


def test_block_rule_does_not_use_text_outside_the_report():
    log = "\n".join(
        [
            _kcsan_report("__fput / kernfs_refresh_inode", ["__fput+0x1/0x2"]),
            "[    2.0] lua-lsm: module <allow-all> registered with 1 filters",
        ]
    )
    fatal, ignored = split_ignored(classify_text(log), (), [KCSAN_LUA_RULE])
    assert [h.pattern for h in ignored] == ["BUG: KCSAN"]
    assert fatal == []


def test_block_rule_catches_short_lua_helper_names():
    log = _kcsan_report("Arith / l_strcmp", ["Arith+0x1/0x2", "l_strcmp+0x3/0x4"])
    fatal, ignored = split_ignored(classify_text(log), (), [KCSAN_LUA_RULE])
    assert ignored == []
    assert [h.pattern for h in fatal] == ["BUG: KCSAN"]


def test_hit_dict_omits_block():
    hit = classify_text("BUG: KCSAN: data-race in a / b\n")[0]
    assert hit.block.startswith("BUG: KCSAN")
    assert "block" not in hit.to_dict()


def test_classify_files_preserves_block(tmp_path):
    log = _kcsan_report("__fput / kernfs_refresh_inode", ["__fput+0x1/0x2"])
    path = tmp_path / "serial.log"
    path.write_text(log + "\n")
    fatal, ignored = split_ignored(classify_files([path]), (), [KCSAN_LUA_RULE])
    assert [h.pattern for h in ignored] == ["BUG: KCSAN"]
    assert fatal == []
