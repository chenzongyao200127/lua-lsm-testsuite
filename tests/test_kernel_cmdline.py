"""Unit tests for guest kernel cmdline composition (harness.kernel_cmdline)."""

import pytest
from harness.kernel_cmdline import (
    BUGHUNT_KNOBS,
    CmdlineError,
    compose,
    compose_env,
)


def test_perf_profile_emits_lsm_and_pool():
    profile = {
        "kind": "perf",
        "lsm": "capability,yama,lua,selinux,bpf,integrity",
        "lvm_pool_max": 64,
    }
    cmdline = compose(profile)
    assert "lsm=capability,yama,lua,selinux,bpf,integrity" in cmdline
    assert "lua.lvm_pool_max=64" in cmdline
    for knob in BUGHUNT_KNOBS:
        assert knob not in cmdline


def test_perf_profile_omits_pool_when_unset():
    profile = {"kind": "perf", "lsm": "capability,lua"}
    assert "lua.lvm_pool_max=" not in compose(profile)


def test_bench_profile_emits_lsm_without_panic_knobs():
    profile = {"kind": "bench", "lsm": "capability,yama,lua"}
    cmdline = compose(profile)
    assert "lsm=capability,yama,lua" in cmdline
    for knob in BUGHUNT_KNOBS:
        assert knob not in cmdline


def test_bughunt_profile_emits_panic_knobs():
    profile = {"kind": "bughunt", "lsm": "lua"}
    cmdline = compose(profile)
    for knob in BUGHUNT_KNOBS:
        assert knob in cmdline


def test_perf_with_injected_panic_knob_is_rejected():
    profile = {"kind": "perf", "extra": ["panic_on_warn=1"]}
    with pytest.raises(CmdlineError):
        compose(profile)


def test_invalid_kind_rejected():
    with pytest.raises(CmdlineError):
        compose({"kind": "weird"})


def test_negative_pool_rejected():
    with pytest.raises(CmdlineError):
        compose({"kind": "perf", "lvm_pool_max": -1})


def test_nodebug_flag():
    profile = {"kind": "perf", "nodebug": True}
    assert "lua.nodebug" in compose(profile)


def test_compose_env_preserves_base_env():
    base = {"PATH": "/usr/bin", "HOST_SSH_PORT": "10024"}
    env = compose_env({"kind": "perf", "lsm": "lua"}, base)
    assert env["PATH"] == "/usr/bin"
    assert env["HOST_SSH_PORT"] == "10024"
    assert "lsm=lua" in env["EXTRA_CMDLINE"]
