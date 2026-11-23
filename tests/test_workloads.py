from pathlib import Path
from unittest.mock import MagicMock

import pytest
from harness import ssh, workloads
from harness.cell_runner import CellContext


def _ctx(art: Path, profile: dict | None = None) -> CellContext:
    return CellContext(
        cell_id="c1",
        artifact_dir=art,
        target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")),
        profile=profile or {},
    )


# --- WorkloadRegistryTests ---


def test_registry_known_workloads():
    assert set(workloads.REGISTRY) == {
        "functional",
        "smoke",
        "bench",
        "bench-short",
        "unixbench",
        "verify-cleanup",
        "concurrency",
        "policy-suite",
        "lkdtm",
    }


def test_bench_short_is_bounded_alias_of_bench(tmp_path, monkeypatch):
    """bench-short MUST behave like `bench` with bounded loops/timeout so
    the default 32-cell smoke matrix completes inside a CI budget."""
    art = tmp_path
    ctx = _ctx(art)
    captured_timeouts: list[float] = []

    def _fake_ssh(target, cmd, timeout_s=120.0):
        captured_timeouts.append(timeout_s)
        return ssh.SshResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ssh, "run", _fake_ssh)
    r = workloads.bench_short(ctx.target, ctx)
    assert r.name == "bench-short"
    assert captured_timeouts, "bench-short must invoke ssh.run"
    # 60s short-timeout default; never the full 1800s bench default.
    assert max(captured_timeouts) <= 60.0


def test_by_name_round_trip():
    for name, fn in workloads.REGISTRY.items():
        assert workloads.by_name(name) is fn


def test_by_name_unknown_raises():
    with pytest.raises(KeyError):
        workloads.by_name("nonexistent-workload")


# --- WorkloadInvocationTests ---


def test_smoke_records_log_on_success(tmp_path, monkeypatch):
    art = tmp_path
    ctx = _ctx(art)
    fake_result = ssh.SshResult(returncode=0, stdout="lua-lsm present\n", stderr="")
    mock_run = MagicMock(return_value=fake_result)
    monkeypatch.setattr(ssh, "run", mock_run)
    r = workloads.smoke(ctx.target, ctx)
    assert r.name == "smoke"
    assert r.returncode == 0
    log = (art / "workload-smoke.log").read_text()
    assert "returncode=0" in log
    assert "lua-lsm present" in log
    # Smoke runs check + register + idle + unregister.
    assert mock_run.call_count >= 3
    # Each guest command was recorded for commands.sh replay.
    assert len(ctx.commands) >= 3
    joined = "\n".join(ctx.commands)
    assert "/sys/kernel/security/lua/register" in joined
    assert "/sys/kernel/security/lua/unregister" in joined


def test_functional_uses_self_contained_fixture(tmp_path, monkeypatch):
    art = tmp_path
    ctx = _ctx(art, profile={"workload_timeout_s": 45})
    fake_result = ssh.SshResult(returncode=0, stdout="ok 9 - policy unloads\n", stderr="")
    mock_run = MagicMock(return_value=fake_result)
    monkeypatch.setattr(ssh, "run", mock_run)
    result = workloads.functional(ctx.target, ctx)
    assert result.name == "functional"
    assert result.returncode == 0
    assert mock_run.call_count == 1
    assert ctx.commands[0] == (
        "bash /mnt/host/lua-lsm-testsuite/fixtures/guest/functional_policy.sh"
    )
    assert "ok 9 - policy unloads" in (art / "workload-functional.log").read_text()


def test_smoke_short_circuits_when_present_check_fails(tmp_path, monkeypatch):
    art = tmp_path
    ctx = _ctx(art)
    fake_result = ssh.SshResult(returncode=1, stdout="", stderr="no securityfs node")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake_result))
    r = workloads.smoke(ctx.target, ctx)
    assert r.returncode == 1
    # Only the presence-check command should have been recorded.
    assert len(ctx.commands) == 1


def test_verify_cleanup_calls_real_helper(tmp_path, monkeypatch):
    art = tmp_path
    ctx = _ctx(art)
    fake_result = ssh.SshResult(returncode=0, stdout="TEST PASSED\n", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake_result))
    r = workloads.verify_cleanup(ctx.target, ctx)
    assert r.returncode == 0
    joined = "\n".join(ctx.commands)
    assert "verify_module_cleanup.sh" in joined


def test_unixbench_uses_wrapper_and_writes_into_share(tmp_path, monkeypatch):
    art = tmp_path
    ctx = _ctx(art, profile={"guest_artifact_relpath": "runs/x/cell"})
    fake_result = ssh.SshResult(returncode=0, stdout="ok\n", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake_result))
    r = workloads.unixbench(ctx.target, ctx)
    assert r.returncode == 0
    joined = "\n".join(ctx.commands)
    assert "/fixtures/guest/unixbench.sh" in joined
    # AC-5.2: the wrapper's -o argument is the cell root itself, NOT
    # a /unixbench subdir; the result tree gets moved to results/
    # by the post-run normalizer.
    assert "-o /mnt/host/runs/x/cell" in joined
    assert "-o /mnt/host/runs/x/cell/unixbench" not in joined


def test_unixbench_build_flag_is_forwarded(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, profile={"unixbench_build": True})
    fake = ssh.SshResult(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    workloads.unixbench(ctx.target, ctx)
    wrapper_cmd = next(c for c in ctx.commands if "unixbench.sh" in c)
    assert wrapper_cmd.endswith(" -b")


def test_unixbench_post_run_layout_matches_ac52(tmp_path, monkeypatch):
    """AC-5.2: after a successful unixbench run, the cell directory must
    contain system.txt, command.txt, unixbench.log at the root AND a
    results/<run-id>/ subdir for the UnixBench result tree."""
    art = tmp_path
    ctx = _ctx(art, profile={"guest_artifact_relpath": "runs/x/cell"})

    # Simulate the unixbench.sh wrapper's output: the wrapper
    # writes three top-level files at -o and copies its latest
    # results-tree as a subdirectory with the UnixBench run-id.
    run_id = "unixbench-2026-05-27-001"

    def _fake_ssh(target, cmd, timeout_s=120.0):
        (art / "system.txt").write_text("Linux 6.10 SELinux\n")
        (art / "command.txt").write_text("/mnt/host/unixbench/Run -c 1 -i 1\n")
        (art / "unixbench.log").write_text("BYTE UNIX Benchmarks 5.1.3\n")
        rd = art / run_id
        rd.mkdir(parents=True, exist_ok=True)
        (rd / "index.html").write_text("<html>results</html>\n")
        (rd / "report-1.txt").write_text("score: 1234\n")
        return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(ssh, "run", _fake_ssh)
    r = workloads.unixbench(ctx.target, ctx)
    assert r.returncode == 0

    # Top-level files land at cell root.
    assert (art / "system.txt").exists()
    assert (art / "system.txt").stat().st_size > 0
    assert (art / "command.txt").exists()
    assert (art / "command.txt").stat().st_size > 0
    assert (art / "unixbench.log").exists()
    assert (art / "unixbench.log").stat().st_size > 0

    # results/<run-id>/ holds the UnixBench result tree; the
    # wrapper's "raw" dir at <cell>/<run-id> is moved away.
    assert not (art / run_id).exists(), "raw <cell>/<run-id> tree must be normalized away"
    normalized = art / "results" / run_id
    assert normalized.exists(), f"expected normalized result tree at {normalized}"
    assert (normalized / "index.html").exists()
    assert (normalized / "report-1.txt").exists()


def test_unixbench_normalizer_leaves_reserved_files_untouched(tmp_path, monkeypatch):
    """Reserved cell-root artifacts (cell.json, dmesg.log, etc.) must
    remain at the cell root even when the unixbench normalizer runs."""
    art = tmp_path
    (art / "cell.json").write_text("{}")
    (art / "dmesg.log").write_text("[ ok ]\n")
    (art / "stats-before.txt").write_text("lvm.nalloc = 0\n")
    ctx = _ctx(art, profile={"guest_artifact_relpath": "runs/x/cell"})

    def _fake_ssh(target, cmd, timeout_s=120.0):
        (art / "system.txt").write_text("sys\n")
        (art / "unixbench-2026-A").mkdir(parents=True, exist_ok=True)
        return ssh.SshResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ssh, "run", _fake_ssh)
    workloads.unixbench(ctx.target, ctx)
    # Reserved files preserved at root.
    assert (art / "cell.json").exists()
    assert (art / "dmesg.log").exists()
    assert (art / "stats-before.txt").exists()
    # Result tree normalized.
    assert (art / "results" / "unixbench-2026-A").exists()


def test_lkdtm_returns_77_when_provoke_missing(tmp_path, monkeypatch):
    art = tmp_path
    ctx = _ctx(art, profile={"lkdtm_kind": "WARNING"})
    fake_result = ssh.SshResult(returncode=77, stdout="LKDTM_PROVOKE_MISSING\n", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake_result))
    r = workloads.lkdtm(ctx.target, ctx)
    assert r.returncode == 77
    assert "CONFIG_LKDTM not enabled" in r.notes


def test_concurrency_requires_policy(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, profile={})
    mock_run = MagicMock()
    monkeypatch.setattr(ssh, "run", mock_run)
    r = workloads.concurrency(ctx.target, ctx)
    assert r.returncode == 2
    assert "requires a policy" in r.notes
    mock_run.assert_not_called()


def test_concurrency_invokes_stress_script(tmp_path, monkeypatch):
    ctx = _ctx(
        tmp_path,
        profile={
            "policy": "smoke",
            "concurrency_workers": 3,
            "concurrency_duration_s": 7,
            "concurrency_cycles": 5,
        },
    )
    fake = ssh.SshResult(returncode=0, stdout="ok 1 - clean\n", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    r = workloads.concurrency(ctx.target, ctx)
    assert r.returncode == 0
    cmd = ctx.commands[0]
    assert "concurrency_stress.sh" in cmd
    assert "/mnt/host/lua-lsm-testsuite/fixtures/policies/smoke.lua" in cmd
    assert cmd.endswith("3 7 5")


def test_policy_suite_requires_policy(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, profile={})
    mock_run = MagicMock()
    monkeypatch.setattr(ssh, "run", mock_run)
    r = workloads.policy_suite(ctx.target, ctx)
    assert r.returncode == 2
    mock_run.assert_not_called()


def test_policy_suite_passes_absolute_policy_path(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, profile={"policy": "/mnt/host/kernel/linux/.github/ci/policies/allow.lua"})
    fake = ssh.SshResult(returncode=0, stdout="ok 1 - clean\n", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    r = workloads.policy_suite(ctx.target, ctx)
    assert r.returncode == 0
    cmd = ctx.commands[0]
    assert "policy_case.sh" in cmd
    assert "/mnt/host/kernel/linux/.github/ci/policies/allow.lua" in cmd


def test_policy_host_path_maps_guest_share_back_to_host(tmp_path):
    guest = "/mnt/host/kernel/linux/.github/ci/policies/allow.lua"
    paths = workloads.policy_host_path(tmp_path, "policy-suite", guest)
    assert paths == (tmp_path / "kernel/linux/.github/ci/policies/allow.lua",)


def test_policy_host_path_passes_bare_host_absolute_through(tmp_path):
    paths = workloads.policy_host_path(tmp_path, "policy-suite", "/opt/policies/allow.lua")
    assert paths == (Path("/opt/policies/allow.lua"),)


# --- PolicyFileGuestPathTests ---
# Round 5 / AC-4: a short policy name (e.g. `hello`) must resolve to
# `<examples>/<name>.lua` so the smoke workload's `test -r <policy>`
# preflight finds the real file on the 9p share. Mirrors the host-side
# normalization in `__main__.py::_resolve_policy_paths`.


@pytest.mark.parametrize(
    ("policy", "expected_guest_path"),
    [
        pytest.param("hello", "/mnt/host/lua-lsm-tools/examples/hello.lua", id="short-name"),
        pytest.param(
            "denyfile.lua", "/mnt/host/lua-lsm-tools/examples/denyfile.lua", id="dot-lua-name"
        ),
        pytest.param(
            "/mnt/host/policies/custom.lua",
            "/mnt/host/policies/custom.lua",
            id="absolute-path",
        ),
        pytest.param(None, "/mnt/host/lua-lsm-tools/examples/hello.lua", id="default"),
    ],
)
def test_policy_name_normalizes_to_guest_path(policy, expected_guest_path):
    assert workloads._policy_file_in_guest(policy) == expected_guest_path


# --- BenchUsesRealLuaContractTests ---
# Round 5 / AC-4: real `lua-lsm-tools/tools/bench.lua` only accepts
# `cmd ∈ {"load", "unload"}` -- anything else prints `Unknown cmd` and
# exits 1. The harness must default to `load` and bench_short must
# issue a paired load + unload; neither path may emit `bench.lua bench`
# (the old broken default).


def test_bench_default_subcommand_is_load(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    fake = ssh.SshResult(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    workloads.bench(ctx.target, ctx)
    assert len(ctx.commands) == 1
    cmd = ctx.commands[0]
    assert "bench.lua" in cmd
    assert " load " in cmd
    assert "bench.lua bench" not in cmd
    assert " bench " not in cmd.replace("bench.lua", "")


def test_bench_short_emits_paired_load_then_unload(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    fake = ssh.SshResult(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    r = workloads.bench_short(ctx.target, ctx)
    assert r.name == "bench-short"
    assert len(ctx.commands) == 2, "bench-short must issue exactly two commands: load + unload"
    assert " load " in ctx.commands[0]
    assert "bench.lua" in ctx.commands[0]
    assert " unload " in ctx.commands[1]
    assert "bench.lua" in ctx.commands[1]
    for cmd in ctx.commands:
        assert "bench.lua bench" not in cmd


def test_bench_short_unload_runs_even_when_load_fails(tmp_path, monkeypatch):
    """If the load step fails the unload step must still execute so
    the next cell starts with the policy unregistered. The cell rc
    surfaces the load failure (the real story), not the unload rc."""
    ctx = _ctx(tmp_path)
    results = iter(
        [
            ssh.SshResult(returncode=1, stdout="", stderr="load failed"),
            ssh.SshResult(returncode=0, stdout="", stderr=""),
        ]
    )

    def _seq(target, cmd, timeout_s=120.0):
        return next(results)

    monkeypatch.setattr(ssh, "run", _seq)
    r = workloads.bench_short(ctx.target, ctx)
    assert len(ctx.commands) == 2
    assert " load " in ctx.commands[0]
    assert " unload " in ctx.commands[1]
    # rc precedence: load failure wins over unload success.
    assert r.returncode == 1


# --- UnixBenchPolicyBracketTests ---
# Round 5 / AC-5.1: perf cells must register the selected policy
# before running UnixBench and unregister after (ALWAYS, even when the
# wrapper fails), so denyfile-driven hook deltas (e.g.
# `file_post_open.count`) are measurable in result.json.perf.


def test_unixbench_brackets_wrapper_with_register_and_unregister(tmp_path, monkeypatch):
    ctx = _ctx(
        tmp_path,
        profile={"guest_artifact_relpath": "runs/x/cell", "policy": "denyfile"},
    )
    fake = ssh.SshResult(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    r = workloads.unixbench(ctx.target, ctx)
    assert r.returncode == 0
    assert len(ctx.commands) == 3, (
        "unixbench must issue exactly three commands: register + wrapper + unregister"
    )
    # Step 1: register denyfile.lua via securityfs.
    assert (
        "cat /mnt/host/lua-lsm-testsuite/fixtures/policies/denyfile.lua "
        "> /sys/kernel/security/lua/register" in ctx.commands[0]
    )
    # Step 2: wrapper invocation.
    assert "/fixtures/guest/unixbench.sh" in ctx.commands[1]
    # Step 3: unregister by short name.
    assert "echo denyfile > /sys/kernel/security/lua/unregister" in ctx.commands[2]


def test_unixbench_policy_none_skips_register_and_unregister(tmp_path, monkeypatch):
    ctx = _ctx(
        tmp_path,
        profile={"guest_artifact_relpath": "runs/x/cell", "policy": "none"},
    )
    fake = ssh.SshResult(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    r = workloads.unixbench(ctx.target, ctx)
    assert r.returncode == 0
    assert len(ctx.commands) == 1, "policy=none must run only the UnixBench wrapper"
    assert "/fixtures/guest/unixbench.sh" in ctx.commands[0]
    assert "/sys/kernel/security/lua/register" not in ctx.commands[0]
    assert "/sys/kernel/security/lua/unregister" not in ctx.commands[0]


def test_unixbench_guest_local_stages_tree_under_tmp(tmp_path, monkeypatch):
    ctx = _ctx(
        tmp_path,
        profile={
            "guest_artifact_relpath": "runs/x/cell",
            "policy": "none",
            "unixbench_guest_local": True,
        },
    )
    fake = ssh.SshResult(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ssh, "run", MagicMock(return_value=fake))
    monkeypatch.setattr(ssh, "fetch_text", MagicMock(return_value=None))
    r = workloads.unixbench(ctx.target, ctx)
    assert r.returncode == 0
    assert len(ctx.commands) == 2, (
        "guest-local unixbench must issue exactly two commands: stage + wrapper"
    )
    assert "cp -a /mnt/host/unixbench/ /tmp/c1-unixbench" in ctx.commands[0]
    assert "/fixtures/guest/unixbench.sh" in ctx.commands[1]
    assert "-d /tmp/c1-unixbench" in ctx.commands[1]
    assert "-o /tmp/c1-lua-lsm-unixbench" in ctx.commands[1]


def test_unixbench_unregisters_even_when_wrapper_fails(tmp_path, monkeypatch):
    """Invariant: a wrapper failure must NOT leak a registered policy
    into the next cell. The unregister step is always issued once
    register succeeded, and the wrapper failure rc is preserved as
    the cell's rc (not masked by a successful unregister)."""
    ctx = _ctx(
        tmp_path,
        profile={"guest_artifact_relpath": "runs/x/cell", "policy": "denyfile"},
    )
    results = iter(
        [
            ssh.SshResult(returncode=0, stdout="", stderr=""),  # register
            ssh.SshResult(returncode=2, stdout="", stderr="UB boom"),  # wrapper
            ssh.SshResult(returncode=0, stdout="", stderr=""),  # unregister
        ]
    )

    def _seq(target, cmd, timeout_s=120.0):
        return next(results)

    monkeypatch.setattr(ssh, "run", _seq)
    r = workloads.unixbench(ctx.target, ctx)
    assert len(ctx.commands) == 3
    assert "echo denyfile > /sys/kernel/security/lua/unregister" in ctx.commands[2]
    # rc precedence: register ok > wrapper fail > unregister ok
    # => wrapper failure is the cell's rc.
    assert r.returncode == 2


def test_unixbench_skips_wrapper_when_register_fails(tmp_path, monkeypatch):
    """If register fails the wrapper is skipped (no policy = perf
    delta would be meaningless), but the unregister step still runs
    as a safety net. The register failure is the surfaced rc."""
    ctx = _ctx(
        tmp_path,
        profile={"guest_artifact_relpath": "runs/x/cell", "policy": "denyfile"},
    )
    results = iter(
        [
            ssh.SshResult(returncode=1, stdout="", stderr="EBUSY"),  # register
            ssh.SshResult(returncode=0, stdout="", stderr=""),  # unregister
        ]
    )

    def _seq(target, cmd, timeout_s=120.0):
        return next(results)

    monkeypatch.setattr(ssh, "run", _seq)
    r = workloads.unixbench(ctx.target, ctx)
    assert len(ctx.commands) == 2
    joined = "\n".join(ctx.commands)
    assert "/fixtures/guest/unixbench.sh" not in joined
    assert r.returncode == 1
    assert "register exited" in (r.notes or "")


def test_unixbench_register_failure_rc_preserved_even_when_unregister_fails(tmp_path, monkeypatch):
    """Round 6 rc-precedence pin: the register failure rc must be
    the cell's rc even when the safety-net unregister also fails
    (e.g. ENOENT because nothing was registered). Without this
    invariant, a stricter unregister rc could mask the load-bearing
    register failure and the cell would silently surface the wrong
    signal."""
    ctx = _ctx(
        tmp_path,
        profile={"guest_artifact_relpath": "runs/x/cell", "policy": "denyfile"},
    )
    results = iter(
        [
            ssh.SshResult(returncode=7, stdout="", stderr="EBUSY"),  # register
            ssh.SshResult(returncode=9, stdout="", stderr="ENOENT"),  # unregister
        ]
    )

    def _seq(target, cmd, timeout_s=120.0):
        return next(results)

    monkeypatch.setattr(ssh, "run", _seq)
    r = workloads.unixbench(ctx.target, ctx)
    assert len(ctx.commands) == 2, "wrapper must remain skipped when register fails"
    assert r.returncode == 7, (
        "register failure (7) must be the cell rc, not the safety-net unregister failure (9)"
    )
    assert "register exited 7" in (r.notes or "")
