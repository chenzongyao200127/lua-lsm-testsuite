"""Perf-cell strict preflight: warm-marker gate + both-halves snapshot.

Moved verbatim from tests/test_round2.py: perf cells skip on a cold
rootfs and require structurally complete stats AND lsm_funcs.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from harness import cell_runner, hostenv, preflight, qemu, schemas, ssh

# ---------------------------------------------------------------------------
# Moved verbatim from tests/test_round2.py (round-2 dissolution).
# ---------------------------------------------------------------------------


def _fake_handle(pid: int = 4242) -> qemu.QemuHandle:
    proc = MagicMock()
    proc.pid = pid
    proc.poll.return_value = 0
    proc.returncode = 0
    return qemu.QemuHandle(
        proc=proc,
        serial_log_path=Path("/tmp/serial.log"),
        pgid=pid,
        started_at=0.0,
    )


def _fake_ssh_ok(target, cmd, timeout_s=120.0):
    return ssh.SshResult(returncode=0, stdout="ok\n", stderr="")


class _PatchHostEnv:
    def __enter__(self):
        self._patch = patch.object(
            hostenv,
            "detect",
            return_value=hostenv.HostEnv(system="Linux", release="6.10.0", has_kvm=True),
        )
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()


def _required_counters_text() -> str:
    from harness import schemas as _s

    return "\n".join(f"{k} = {i}" for i, k in enumerate(_s.REQUIRED_COUNTER_KEYS)) + "\n"


def _valid_funcs_text() -> str:
    return (
        "stats for lua-lsm (ns)\n"
        "num name                         nlsm        "
        "count           total    average      maxtime\n"
        "----\n"
        "  1 inode_permission             1           5               500      100         200\n"
    )


class PerfImageWarmPreflightTests(unittest.TestCase):
    def _perf_inputs(self, art: Path, rootfs: Path) -> cell_runner.CellInputs:
        return cell_runner.CellInputs(
            cell_id="perf_cell",
            profile={"kind": "perf"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench"),
            workload_name="bench",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(
                host="127.0.0.1", port=10024, user="root", key_path=Path("/dev/null")
            ),
            kvm_required=False,
            rootfs_image=rootfs,
        )

    def test_perf_cell_skips_with_image_not_warm_and_never_spawns(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            # No `<rootfs>.warm-marker` -> preflight must skip.

            def _fail_spawn(*a, **kw):
                raise AssertionError("qemu.spawn must not be invoked for a cold-rootfs perf cell")

            inputs = self._perf_inputs(art, rootfs)
            with _PatchHostEnv(), patch.object(qemu, "spawn", side_effect=_fail_spawn):
                out = cell_runner.run_cell(inputs)
            self.assertEqual(out["verdict"], "skip:image-not-warm")
            self.assertTrue((art / "result.json").exists())
            # Perf payload must remain the schema's null default (no snapshots
            # were taken) so consumers can distinguish a skipped perf cell from
            # one with measured deltas.
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_cell_proceeds_when_warm_marker_present(self):
        # Marker present -> the preflight gate must NOT short-circuit and
        # qemu.spawn must be reached. We mock the spawn to fail cleanly so we
        # can detect the gate decision without booting a real VM.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            preflight.default_warm_marker(rootfs).write_text("warm\n")
            sentinel = []

            def _spawn_sentinel(*a, **kw):
                sentinel.append(True)
                raise qemu.QemuLaunchError("test-only: stopped before boot")

            inputs = self._perf_inputs(art, rootfs)
            with _PatchHostEnv(), patch.object(qemu, "spawn", side_effect=_spawn_sentinel):
                out = cell_runner.run_cell(inputs)
            self.assertTrue(sentinel, "qemu.spawn must be reached when marker exists")
            # The harness-error verdict comes from the simulated launch failure.
            self.assertEqual(out["verdict"], "harness-error")

    def test_bughunt_cell_ignores_warm_marker(self):
        # Image warmth only gates perf cells; bughunt must NOT skip on a cold
        # rootfs (correctness cells boot a fresh kernel deliberately).
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "bug"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            inputs = cell_runner.CellInputs(
                cell_id="bug_cell",
                profile={"kind": "bughunt"},
                workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
                workload_name="noop",
                launcher=Path("/nonexistent/run.sh"),
                artifact_dir=art,
                ssh_target=ssh.SshTarget(
                    host="127.0.0.1", port=10025, user="root", key_path=Path("/dev/null")
                ),
                kvm_required=False,
                rootfs_image=rootfs,
            )
            spawn_calls = []

            def _spawn_count(*a, **kw):
                spawn_calls.append(True)
                raise qemu.QemuLaunchError("test-only")

            with _PatchHostEnv(), patch.object(qemu, "spawn", side_effect=_spawn_count):
                out = cell_runner.run_cell(inputs)
            self.assertTrue(spawn_calls, "bughunt cell must still attempt qemu.spawn")
            self.assertNotEqual(out["verdict"], "skip:image-not-warm")


class PerfStrictBothRequiredTests(unittest.TestCase):
    def _perf_inputs_warm(self, art: Path, rootfs: Path) -> cell_runner.CellInputs:
        # Pre-warm the rootfs so the image-warm gate (the *other* perf
        # preflight) does not steal the test's intent.
        preflight.default_warm_marker(rootfs).write_text("warm\n")
        return cell_runner.CellInputs(
            cell_id="perf_cell",
            profile={"kind": "perf"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench"),
            workload_name="bench",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(
                host="127.0.0.1", port=10026, user="root", key_path=Path("/dev/null")
            ),
            kvm_required=False,
            rootfs_image=rootfs,
        )

    def _run_perf_with_fetch(
        self,
        art: Path,
        rootfs: Path,
        stats_text: str | None,
        funcs_text: str | None,
        workload_invoked: list[bool],
    ) -> dict:
        inputs = self._perf_inputs_warm(art, rootfs)

        def _wl(target, ctx):
            workload_invoked.append(True)
            return cell_runner.WorkloadResult(name="bench", returncode=0)

        # Replace the workload with our sentinel so we can detect whether
        # the strict-both gate skipped the workload.
        inputs = cell_runner.CellInputs(
            **{**inputs.__dict__, "workload_fn": _wl},
        )

        fetch_iter = iter([(stats_text, funcs_text), (stats_text, funcs_text)])

        def _fetch_pair(target):
            try:
                return next(fetch_iter)
            except StopIteration:
                return (stats_text, funcs_text)

        with (
            _PatchHostEnv(),
            patch.object(qemu, "spawn", return_value=_fake_handle()),
            patch.object(qemu, "stop", return_value=0),
            patch.object(ssh, "wait_for_ssh", return_value=True),
            patch.object(ssh, "run", side_effect=_fake_ssh_ok),
            patch.object(cell_runner, "_fetch_perf_texts", side_effect=_fetch_pair),
        ):
            return cell_runner.run_cell(inputs)

    def _stats_text(self) -> str:
        # Use the real REQUIRED_COUNTER_KEYS so the strict validator accepts
        # the snapshot. AC-5.1 requires every key in REQUIRED_COUNTER_KEYS to
        # be present before a perf cell is considered measurable.
        lines = [f"{k} = {i}" for i, k in enumerate(schemas.REQUIRED_COUNTER_KEYS)]
        return "\n".join(lines) + "\n"

    def _funcs_text(self) -> str:
        return (
            "stats for lua-lsm (ns)\n"
            "num name                         nlsm        "
            "count           total    average      maxtime\n"
            "----\n"
            "  1 inode_permission             1           "
            "5               500      100         200\n"
        )

    def test_perf_skip_when_only_stats_present(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art,
                rootfs,
                stats_text=self._stats_text(),
                funcs_text=None,
                workload_invoked=workload_invoked,
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(workload_invoked, "workload must not run when perf preflight skips")
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_skip_when_only_lsm_funcs_present(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art,
                rootfs,
                stats_text=None,
                funcs_text=self._funcs_text(),
                workload_invoked=workload_invoked,
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(workload_invoked)
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_skip_when_both_missing(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art,
                rootfs,
                stats_text=None,
                funcs_text=None,
                workload_invoked=workload_invoked,
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(workload_invoked)
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_perf_runs_when_both_present(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "perf"
            rootfs = tdp / "rootfs.img"
            rootfs.write_bytes(b"")
            (art).mkdir(parents=True, exist_ok=True)
            (art / "dmesg.log").write_text("[    0.000] Linux version 6.10\n")
            workload_invoked: list[bool] = []
            out = self._run_perf_with_fetch(
                art,
                rootfs,
                stats_text=self._stats_text(),
                funcs_text=self._funcs_text(),
                workload_invoked=workload_invoked,
            )
            self.assertTrue(workload_invoked, "workload must run when both files present")
            self.assertNotIn("skip:stats-unavailable", str(out.get("verdict")))
            self.assertIsNotNone(out.get("perf"))


class PerfStrictValidatesCountersTests(unittest.TestCase):
    """Drive `run_cell` end-to-end with mocked SSH/QEMU and feed it
    intentionally-malformed perf telemetry for either the before-snapshot or
    the after-snapshot. The strict path MUST reject both forms with
    skip:stats-unavailable; the workload MUST NOT see partial-delta passes.
    """

    def _perf_inputs_warm(self, art: Path, rootfs: Path) -> cell_runner.CellInputs:
        preflight.default_warm_marker(rootfs).write_text("warm\n")
        return cell_runner.CellInputs(
            cell_id="perf_cell",
            profile={"kind": "perf"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="bench", returncode=0),
            workload_name="bench",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(
                host="127.0.0.1", port=10027, user="root", key_path=Path("/dev/null")
            ),
            kvm_required=False,
            rootfs_image=rootfs,
        )

    def _run(
        self,
        art: Path,
        rootfs: Path,
        before_pair: tuple[str | None, str | None],
        after_pair: tuple[str | None, str | None],
    ) -> dict:
        inputs = self._perf_inputs_warm(art, rootfs)
        workload_invoked: list[bool] = []

        def _wl(target, ctx):
            workload_invoked.append(True)
            return cell_runner.WorkloadResult(name="bench", returncode=0)

        inputs = cell_runner.CellInputs(
            **{**inputs.__dict__, "workload_fn": _wl},
        )

        # First _fetch_perf_texts call is BEFORE, second is AFTER. Any further
        # call (defensive) returns the after pair so we don't trip StopIteration.
        pairs = iter([before_pair, after_pair])

        def _fetch(target):
            try:
                return next(pairs)
            except StopIteration:
                return after_pair

        art.mkdir(parents=True, exist_ok=True)
        (art / "dmesg.log").write_text("[    0.000] Linux version 6.10\n")

        with (
            _PatchHostEnv(),
            patch.object(qemu, "spawn", return_value=_fake_handle()),
            patch.object(qemu, "stop", return_value=0),
            patch.object(ssh, "wait_for_ssh", return_value=True),
            patch.object(ssh, "run", side_effect=_fake_ssh_ok),
            patch.object(cell_runner, "_fetch_perf_texts", side_effect=_fetch),
        ):
            result = cell_runner.run_cell(inputs)
        result["__workload_invoked__"] = bool(workload_invoked)
        return result

    def test_malformed_before_counters_skips_without_workload_spawn(self):
        bad_stats = "lvm.alloc_count = 1\nlvm.alloc_total_ns = 1000\n"  # not REQUIRED keys
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf",
                tdp / "rootfs.img",
                before_pair=(bad_stats, _valid_funcs_text()),
                after_pair=(_required_counters_text(), _valid_funcs_text()),
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertIn("malformed", out["reason"])
            self.assertFalse(
                out["__workload_invoked__"],
                "workload must not run when before-snapshot is malformed",
            )
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_malformed_before_lsm_funcs_skips_without_workload_spawn(self):
        empty_funcs = "stats for lua-lsm (ns)\n"  # header only, no rows
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf",
                tdp / "rootfs.img",
                before_pair=(_required_counters_text(), empty_funcs),
                after_pair=(_required_counters_text(), _valid_funcs_text()),
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertFalse(out["__workload_invoked__"])
            self.assertIsNone(out["perf"].get("snapshots"))

    def test_malformed_after_counters_skips_no_partial_deltas(self):
        bad_stats = "lvm.alloc_count = 1\n"
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf",
                tdp / "rootfs.img",
                before_pair=(_required_counters_text(), _valid_funcs_text()),
                after_pair=(bad_stats, _valid_funcs_text()),
            )
            self.assertEqual(
                out["verdict"], "skip:stats-unavailable", f"got verdict={out.get('verdict')!r}"
            )
            self.assertTrue(
                out["__workload_invoked__"], "workload runs when before-snapshot is valid"
            )
            self.assertIn("malformed", out["reason"])
            self.assertIsNone(
                out["perf"].get("snapshots"),
                "malformed-after must NOT emit partial-delta snapshots",
            )
            self.assertIsNone(out["perf"].get("deltas"))

    def test_malformed_after_lsm_funcs_skips_no_partial_deltas(self):
        empty_funcs = "stats for lua-lsm (ns)\n"
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf",
                tdp / "rootfs.img",
                before_pair=(_required_counters_text(), _valid_funcs_text()),
                after_pair=(_required_counters_text(), empty_funcs),
            )
            self.assertEqual(out["verdict"], "skip:stats-unavailable")
            self.assertTrue(out["__workload_invoked__"])
            self.assertIsNone(out["perf"].get("snapshots"))
            self.assertIsNone(out["perf"].get("deltas"))

    def test_valid_both_sides_produces_full_deltas_and_pass(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            out = self._run(
                tdp / "perf",
                tdp / "rootfs.img",
                before_pair=(_required_counters_text(), _valid_funcs_text()),
                after_pair=(_required_counters_text(), _valid_funcs_text()),
            )
            self.assertEqual(out["verdict"], "pass", f"got verdict={out.get('verdict')!r}")
            self.assertIsNotNone(out["perf"]["snapshots"])
            self.assertIn("before", out["perf"]["snapshots"])
            self.assertIn("after", out["perf"]["snapshots"])
            self.assertIsNotNone(out["perf"]["deltas"])


if __name__ == "__main__":
    import unittest

    unittest.main()
