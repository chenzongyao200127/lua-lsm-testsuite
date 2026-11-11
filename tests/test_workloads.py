import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness import ssh, workloads
from harness.cell_runner import CellContext


class WorkloadRegistryTests(unittest.TestCase):
    def test_registry_known_workloads(self):
        self.assertEqual(
            set(workloads.REGISTRY),
            {"functional", "smoke", "bench", "bench-short", "unixbench",
             "verify-cleanup", "lkdtm"},
        )

    def test_bench_short_is_bounded_alias_of_bench(self):
        """bench-short MUST behave like `bench` with bounded loops/timeout so
        the default 32-cell smoke matrix completes inside a CI budget."""
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = CellContext(
                cell_id="c1",
                artifact_dir=art,
                target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                     key_path=Path("/dev/null")),
                profile={},
            )
            captured_timeouts: list[float] = []

            def _fake_ssh(target, cmd, timeout_s=120.0):
                captured_timeouts.append(timeout_s)
                return ssh.SshResult(returncode=0, stdout="", stderr="")

            with patch.object(ssh, "run", side_effect=_fake_ssh):
                r = workloads.bench_short(ctx.target, ctx)
            self.assertEqual(r.name, "bench-short")
            self.assertTrue(captured_timeouts, "bench-short must invoke ssh.run")
            # 60s short-timeout default; never the full 1800s bench default.
            self.assertLessEqual(max(captured_timeouts), 60.0)

    def test_by_name_round_trip(self):
        for name, fn in workloads.REGISTRY.items():
            self.assertIs(workloads.by_name(name), fn)

    def test_by_name_unknown_raises(self):
        with self.assertRaises(KeyError):
            workloads.by_name("nonexistent-workload")


class WorkloadInvocationTests(unittest.TestCase):
    def _ctx(self, art: Path, profile: dict | None = None) -> CellContext:
        return CellContext(
            cell_id="c1",
            artifact_dir=art,
            target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")),
            profile=profile or {},
        )

    def test_smoke_records_log_on_success(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = self._ctx(art)
            fake_result = ssh.SshResult(returncode=0, stdout="lua-lsm present\n", stderr="")
            with patch.object(ssh, "run", return_value=fake_result) as mock_run:
                r = workloads.smoke(ctx.target, ctx)
            self.assertEqual(r.name, "smoke")
            self.assertEqual(r.returncode, 0)
            log = (art / "workload-smoke.log").read_text()
            self.assertIn("returncode=0", log)
            self.assertIn("lua-lsm present", log)
            # Smoke runs check + register + idle + unregister.
            self.assertGreaterEqual(mock_run.call_count, 3)
            # Each guest command was recorded for commands.sh replay.
            self.assertGreaterEqual(len(ctx.commands), 3)
            joined = "\n".join(ctx.commands)
            self.assertIn("/sys/kernel/security/lua/register", joined)
            self.assertIn("/sys/kernel/security/lua/unregister", joined)

    def test_functional_uses_self_contained_fixture(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = self._ctx(art, profile={"workload_timeout_s": 45})
            fake_result = ssh.SshResult(
                returncode=0, stdout="ok 9 - policy unloads\n", stderr=""
            )
            with patch.object(ssh, "run", return_value=fake_result) as mock_run:
                result = workloads.functional(ctx.target, ctx)
            self.assertEqual(result.name, "functional")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(mock_run.call_count, 1)
            self.assertEqual(
                ctx.commands[0],
                "bash /mnt/host/lua-lsm-testsuite/fixtures/guest/functional_policy.sh",
            )
            self.assertIn(
                "ok 9 - policy unloads",
                (art / "workload-functional.log").read_text(),
            )

    def test_smoke_short_circuits_when_present_check_fails(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = self._ctx(art)
            fake_result = ssh.SshResult(returncode=1, stdout="", stderr="no securityfs node")
            with patch.object(ssh, "run", return_value=fake_result):
                r = workloads.smoke(ctx.target, ctx)
            self.assertEqual(r.returncode, 1)
            # Only the presence-check command should have been recorded.
            self.assertEqual(len(ctx.commands), 1)

    def test_verify_cleanup_calls_real_helper(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = self._ctx(art)
            fake_result = ssh.SshResult(returncode=0, stdout="TEST PASSED\n", stderr="")
            with patch.object(ssh, "run", return_value=fake_result):
                r = workloads.verify_cleanup(ctx.target, ctx)
            self.assertEqual(r.returncode, 0)
            joined = "\n".join(ctx.commands)
            self.assertIn("verify_module_cleanup.sh", joined)

    def test_unixbench_uses_wrapper_and_writes_into_share(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = self._ctx(art, profile={"guest_artifact_relpath": "runs/x/cell"})
            fake_result = ssh.SshResult(returncode=0, stdout="ok\n", stderr="")
            with patch.object(ssh, "run", return_value=fake_result):
                r = workloads.unixbench(ctx.target, ctx)
            self.assertEqual(r.returncode, 0)
            joined = "\n".join(ctx.commands)
            self.assertIn("lua_lsm_unixbench.sh", joined)
            # AC-5.2: the wrapper's -o argument is the cell root itself, NOT
            # a /unixbench subdir; the result tree gets moved to results/
            # by the post-run normalizer.
            self.assertIn("-o /mnt/host/runs/x/cell", joined)
            self.assertNotIn("-o /mnt/host/runs/x/cell/unixbench", joined)

    def test_unixbench_post_run_layout_matches_ac52(self):
        """AC-5.2: after a successful unixbench run, the cell directory must
        contain system.txt, command.txt, unixbench.log at the root AND a
        results/<run-id>/ subdir for the UnixBench result tree."""
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = self._ctx(art, profile={"guest_artifact_relpath": "runs/x/cell"})

            # Simulate the lua_lsm_unixbench.sh wrapper's output: the wrapper
            # writes three top-level files at -o and copies its latest
            # results-tree as a subdirectory with the UnixBench run-id.
            run_id = "unixbench-2026-05-27-001"
            def _fake_ssh(target, cmd, timeout_s=120.0):
                (art / "system.txt").write_text("Linux 6.10 SELinux\n")
                (art / "command.txt").write_text(
                    "/mnt/host/unixbench/Run -c 1 -i 1\n"
                )
                (art / "unixbench.log").write_text("BYTE UNIX Benchmarks 5.1.3\n")
                rd = art / run_id
                rd.mkdir(parents=True, exist_ok=True)
                (rd / "index.html").write_text("<html>results</html>\n")
                (rd / "report-1.txt").write_text("score: 1234\n")
                return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")

            with patch.object(ssh, "run", side_effect=_fake_ssh):
                r = workloads.unixbench(ctx.target, ctx)
            self.assertEqual(r.returncode, 0)

            # Top-level files land at cell root.
            self.assertTrue((art / "system.txt").exists())
            self.assertGreater((art / "system.txt").stat().st_size, 0)
            self.assertTrue((art / "command.txt").exists())
            self.assertGreater((art / "command.txt").stat().st_size, 0)
            self.assertTrue((art / "unixbench.log").exists())
            self.assertGreater((art / "unixbench.log").stat().st_size, 0)

            # results/<run-id>/ holds the UnixBench result tree; the
            # wrapper's "raw" dir at <cell>/<run-id> is moved away.
            self.assertFalse((art / run_id).exists(),
                             "raw <cell>/<run-id> tree must be normalized away")
            normalized = art / "results" / run_id
            self.assertTrue(normalized.exists(),
                            f"expected normalized result tree at {normalized}")
            self.assertTrue((normalized / "index.html").exists())
            self.assertTrue((normalized / "report-1.txt").exists())

    def test_unixbench_normalizer_leaves_reserved_files_untouched(self):
        """Reserved cell-root artifacts (cell.json, dmesg.log, etc.) must
        remain at the cell root even when the unixbench normalizer runs."""
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "cell.json").write_text("{}")
            (art / "dmesg.log").write_text("[ ok ]\n")
            (art / "stats-before.txt").write_text("lvm.nalloc = 0\n")
            ctx = self._ctx(art, profile={"guest_artifact_relpath": "runs/x/cell"})

            def _fake_ssh(target, cmd, timeout_s=120.0):
                (art / "system.txt").write_text("sys\n")
                (art / "unixbench-2026-A").mkdir(parents=True, exist_ok=True)
                return ssh.SshResult(returncode=0, stdout="", stderr="")

            with patch.object(ssh, "run", side_effect=_fake_ssh):
                workloads.unixbench(ctx.target, ctx)
            # Reserved files preserved at root.
            self.assertTrue((art / "cell.json").exists())
            self.assertTrue((art / "dmesg.log").exists())
            self.assertTrue((art / "stats-before.txt").exists())
            # Result tree normalized.
            self.assertTrue((art / "results" / "unixbench-2026-A").exists())

    def test_lkdtm_returns_77_when_provoke_missing(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            ctx = self._ctx(art, profile={"lkdtm_kind": "WARNING"})
            fake_result = ssh.SshResult(returncode=77, stdout="LKDTM_PROVOKE_MISSING\n", stderr="")
            with patch.object(ssh, "run", return_value=fake_result):
                r = workloads.lkdtm(ctx.target, ctx)
            self.assertEqual(r.returncode, 77)
            self.assertIn("CONFIG_LKDTM not enabled", r.notes)


class PolicyFileGuestPathTests(unittest.TestCase):
    """Round 5 / AC-4: a short policy name (e.g. `hello`) must resolve to
    `<examples>/<name>.lua` so the smoke workload's `test -r <policy>`
    preflight finds the real file on the 9p share. Mirrors the host-side
    normalization in `__main__.py::_resolve_policy_paths`."""

    def test_short_name_gains_lua_suffix(self):
        self.assertEqual(
            workloads._policy_file_in_guest("hello"),
            "/mnt/host/lua-lsm-tools/examples/hello.lua",
        )

    def test_dot_lua_name_passes_through(self):
        self.assertEqual(
            workloads._policy_file_in_guest("denyfile.lua"),
            "/mnt/host/lua-lsm-tools/examples/denyfile.lua",
        )

    def test_absolute_path_passes_through_unchanged(self):
        self.assertEqual(
            workloads._policy_file_in_guest("/mnt/host/policies/custom.lua"),
            "/mnt/host/policies/custom.lua",
        )

    def test_default_when_policy_unset_is_hello_dot_lua(self):
        self.assertEqual(
            workloads._policy_file_in_guest(None),
            "/mnt/host/lua-lsm-tools/examples/hello.lua",
        )


class BenchUsesRealLuaContractTests(unittest.TestCase):
    """Round 5 / AC-4: real `lua-lsm-tools/tools/bench.lua` only accepts
    `cmd ∈ {"load", "unload"}` -- anything else prints `Unknown cmd` and
    exits 1. The harness must default to `load` and bench_short must
    issue a paired load + unload; neither path may emit `bench.lua bench`
    (the old broken default)."""

    def _ctx(self, art: Path, profile: dict | None = None) -> CellContext:
        return CellContext(
            cell_id="c1",
            artifact_dir=art,
            target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                 key_path=Path("/dev/null")),
            profile=profile or {},
        )

    def test_bench_default_subcommand_is_load(self):
        with TemporaryDirectory() as td:
            ctx = self._ctx(Path(td))
            fake = ssh.SshResult(returncode=0, stdout="", stderr="")
            with patch.object(ssh, "run", return_value=fake):
                workloads.bench(ctx.target, ctx)
            self.assertEqual(len(ctx.commands), 1)
            cmd = ctx.commands[0]
            self.assertIn("bench.lua", cmd)
            self.assertIn(" load ", cmd)
            self.assertNotIn("bench.lua bench", cmd)
            self.assertNotIn(" bench ", cmd.replace("bench.lua", ""))

    def test_bench_short_emits_paired_load_then_unload(self):
        with TemporaryDirectory() as td:
            ctx = self._ctx(Path(td))
            fake = ssh.SshResult(returncode=0, stdout="", stderr="")
            with patch.object(ssh, "run", return_value=fake):
                r = workloads.bench_short(ctx.target, ctx)
            self.assertEqual(r.name, "bench-short")
            self.assertEqual(
                len(ctx.commands), 2,
                "bench-short must issue exactly two commands: load + unload",
            )
            self.assertIn(" load ", ctx.commands[0])
            self.assertIn("bench.lua", ctx.commands[0])
            self.assertIn(" unload ", ctx.commands[1])
            self.assertIn("bench.lua", ctx.commands[1])
            for cmd in ctx.commands:
                self.assertNotIn("bench.lua bench", cmd)

    def test_bench_short_unload_runs_even_when_load_fails(self):
        """If the load step fails the unload step must still execute so
        the next cell starts with the policy unregistered. The cell rc
        surfaces the load failure (the real story), not the unload rc."""
        with TemporaryDirectory() as td:
            ctx = self._ctx(Path(td))
            results = iter([
                ssh.SshResult(returncode=1, stdout="", stderr="load failed"),
                ssh.SshResult(returncode=0, stdout="", stderr=""),
            ])

            def _seq(target, cmd, timeout_s=120.0):
                return next(results)

            with patch.object(ssh, "run", side_effect=_seq):
                r = workloads.bench_short(ctx.target, ctx)
            self.assertEqual(len(ctx.commands), 2)
            self.assertIn(" load ", ctx.commands[0])
            self.assertIn(" unload ", ctx.commands[1])
            # rc precedence: load failure wins over unload success.
            self.assertEqual(r.returncode, 1)


class UnixBenchPolicyBracketTests(unittest.TestCase):
    """Round 5 / AC-5.1: perf cells must register the selected policy
    before running UnixBench and unregister after (ALWAYS, even when the
    wrapper fails), so denyfile-driven hook deltas (e.g.
    `file_post_open.count`) are measurable in result.json.perf."""

    def _ctx(self, art: Path, profile: dict | None = None) -> CellContext:
        return CellContext(
            cell_id="c1",
            artifact_dir=art,
            target=ssh.SshTarget(host="127.0.0.1", port=10023, user="root",
                                 key_path=Path("/dev/null")),
            profile=profile or {},
        )

    def test_unixbench_brackets_wrapper_with_register_and_unregister(self):
        with TemporaryDirectory() as td:
            ctx = self._ctx(
                Path(td),
                profile={"guest_artifact_relpath": "runs/x/cell",
                         "policy": "denyfile"},
            )
            fake = ssh.SshResult(returncode=0, stdout="", stderr="")
            with patch.object(ssh, "run", return_value=fake):
                r = workloads.unixbench(ctx.target, ctx)
            self.assertEqual(r.returncode, 0)
            self.assertEqual(
                len(ctx.commands), 3,
                "unixbench must issue exactly three commands: "
                "register + wrapper + unregister",
            )
            # Step 1: register denyfile.lua via securityfs.
            self.assertIn(
                "cat /mnt/host/lua-lsm-tools/examples/denyfile.lua "
                "> /sys/kernel/security/lua/register",
                ctx.commands[0],
            )
            # Step 2: wrapper invocation.
            self.assertIn("lua_lsm_unixbench.sh", ctx.commands[1])
            # Step 3: unregister by short name.
            self.assertIn(
                "echo denyfile > /sys/kernel/security/lua/unregister",
                ctx.commands[2],
            )

    def test_unixbench_unregisters_even_when_wrapper_fails(self):
        """Invariant: a wrapper failure must NOT leak a registered policy
        into the next cell. The unregister step is always issued once
        register succeeded, and the wrapper failure rc is preserved as
        the cell's rc (not masked by a successful unregister)."""
        with TemporaryDirectory() as td:
            ctx = self._ctx(
                Path(td),
                profile={"guest_artifact_relpath": "runs/x/cell",
                         "policy": "denyfile"},
            )
            results = iter([
                ssh.SshResult(returncode=0, stdout="", stderr=""),       # register
                ssh.SshResult(returncode=2, stdout="", stderr="UB boom"),# wrapper
                ssh.SshResult(returncode=0, stdout="", stderr=""),       # unregister
            ])

            def _seq(target, cmd, timeout_s=120.0):
                return next(results)

            with patch.object(ssh, "run", side_effect=_seq):
                r = workloads.unixbench(ctx.target, ctx)
            self.assertEqual(len(ctx.commands), 3)
            self.assertIn(
                "echo denyfile > /sys/kernel/security/lua/unregister",
                ctx.commands[2],
            )
            # rc precedence: register ok > wrapper fail > unregister ok
            # => wrapper failure is the cell's rc.
            self.assertEqual(r.returncode, 2)

    def test_unixbench_skips_wrapper_when_register_fails(self):
        """If register fails the wrapper is skipped (no policy = perf
        delta would be meaningless), but the unregister step still runs
        as a safety net. The register failure is the surfaced rc."""
        with TemporaryDirectory() as td:
            ctx = self._ctx(
                Path(td),
                profile={"guest_artifact_relpath": "runs/x/cell",
                         "policy": "denyfile"},
            )
            results = iter([
                ssh.SshResult(returncode=1, stdout="", stderr="EBUSY"),  # register
                ssh.SshResult(returncode=0, stdout="", stderr=""),       # unregister
            ])

            def _seq(target, cmd, timeout_s=120.0):
                return next(results)

            with patch.object(ssh, "run", side_effect=_seq):
                r = workloads.unixbench(ctx.target, ctx)
            self.assertEqual(len(ctx.commands), 2)
            joined = "\n".join(ctx.commands)
            self.assertNotIn("lua_lsm_unixbench.sh", joined)
            self.assertEqual(r.returncode, 1)
            self.assertIn("register exited", r.notes or "")

    def test_unixbench_register_failure_rc_preserved_even_when_unregister_fails(self):
        """Round 6 rc-precedence pin: the register failure rc must be
        the cell's rc even when the safety-net unregister also fails
        (e.g. ENOENT because nothing was registered). Without this
        invariant, a stricter unregister rc could mask the load-bearing
        register failure and the cell would silently surface the wrong
        signal."""
        with TemporaryDirectory() as td:
            ctx = self._ctx(
                Path(td),
                profile={"guest_artifact_relpath": "runs/x/cell",
                         "policy": "denyfile"},
            )
            results = iter([
                ssh.SshResult(returncode=7, stdout="", stderr="EBUSY"),     # register
                ssh.SshResult(returncode=9, stdout="", stderr="ENOENT"),    # unregister
            ])

            def _seq(target, cmd, timeout_s=120.0):
                return next(results)

            with patch.object(ssh, "run", side_effect=_seq):
                r = workloads.unixbench(ctx.target, ctx)
            self.assertEqual(len(ctx.commands), 2,
                             "wrapper must remain skipped when register fails")
            self.assertEqual(r.returncode, 7,
                             "register failure (7) must be the cell rc, "
                             "not the safety-net unregister failure (9)")
            self.assertIn("register exited 7", r.notes or "")


if __name__ == "__main__":
    unittest.main()
