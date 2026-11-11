import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness import cell_runner, perf_snapshot, ssh
from harness.hostenv import HostEnv


def _inputs(
    art: Path, *, kvm_required: bool, profile: dict | None = None, workload_name: str = "noop"
) -> cell_runner.CellInputs:
    profile = profile or {"kind": "perf", "lsm": "capability,bpf,lua", "lvm_pool_max": 16}
    return cell_runner.CellInputs(
        cell_id="test_cell",
        profile=profile,
        workload_fn=lambda t, c: cell_runner.WorkloadResult(name=workload_name),
        workload_name=workload_name,
        launcher=Path("/nonexistent/run.sh"),
        artifact_dir=art,
        ssh_target=ssh.SshTarget(
            host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")
        ),
        kvm_required=kvm_required,
    )


def _finalize_args(art: Path):
    """Build the (result, art, inputs, ctx, workload_rc) tuple for _classify_and_finalize."""
    inputs = _inputs(art, kvm_required=False, profile={"kind": "perf"})
    ctx = cell_runner.CellContext(
        cell_id=inputs.cell_id,
        artifact_dir=art,
        target=inputs.ssh_target,
        profile=inputs.profile,
    )
    return inputs, ctx


class CellRunnerTests(unittest.TestCase):
    def test_skip_no_kvm_writes_result_without_spawning(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            host = HostEnv(system="Linux", release="6.10.0", has_kvm=False)
            r = cell_runner.run_cell(_inputs(art, kvm_required=True), host=host)
            self.assertEqual(r["verdict"], "skip:no-kvm")
            self.assertIsNotNone(r["finished_at"])
            self.assertTrue((art / "result.json").exists())
            on_disk = json.loads((art / "result.json").read_text())
            self.assertEqual(on_disk["verdict"], "skip:no-kvm")
            self.assertEqual(on_disk["host"]["has_kvm"], False)

    def test_make_cell_id_is_deterministic_modulo_time(self):
        a = cell_runner._make_cell_id({"k": 1}, "smoke")
        b = cell_runner._make_cell_id({"k": 1}, "smoke")
        # Hash suffix derives from inputs alone; the two ids share that suffix.
        self.assertEqual(a.split("_", 1)[1], b.split("_", 1)[1])

    def test_persist_snapshot_round_trips(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            snap = perf_snapshot.Snapshot(
                counters={"lvm.nalloc": 100, "kvcache.nusage": 5},
                lsm_funcs={
                    "file_open": {
                        "nlsm": 1,
                        "count": 5,
                        "total": 5000,
                        "average": 1000,
                        "maxtime": 2500,
                    }
                },
            )
            cell_runner._persist_snapshot(art, "before", snap)
            stats_back = perf_snapshot.parse_stats_text((art / "stats-before.txt").read_text())
            self.assertEqual(stats_back, snap.counters)
            funcs_back = perf_snapshot.parse_lsm_funcs_text(
                (art / "lsm_funcs-before.txt").read_text()
            )
            self.assertEqual(funcs_back["file_open"]["count"], 5)
            self.assertEqual(funcs_back["file_open"]["maxtime"], 2500)

    def test_finalize_no_logs_emits_no_dmesg(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            from harness.schemas import empty_result

            r = empty_result("c1")
            inputs, ctx = _finalize_args(art)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, None)
            self.assertEqual(out["verdict"], "no-dmesg")
            self.assertTrue((art / "result.json").exists())

    def test_finalize_clean_log_passes(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "dmesg.log").write_text(
                "[    0.000000] Linux version 6.10\n[    1.234567] Hello\n"
            )
            from harness.schemas import empty_result

            r = empty_result("c1")
            inputs, ctx = _finalize_args(art)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, None)
            self.assertEqual(out["verdict"], "pass")
            self.assertEqual(out["classifier_hits"], [])

    def test_finalize_kasan_log_is_kernel_bug(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "dmesg.log").write_text(
                "[    1.0] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30\n"
            )
            from harness.schemas import empty_result

            r = empty_result("c1")
            inputs, ctx = _finalize_args(art)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, None)
            self.assertEqual(out["verdict"], "kernel-bug")
            self.assertGreater(len(out["classifier_hits"]), 0)

    def test_finalize_empty_log_files_emit_no_dmesg(self):
        # Zero-byte serial.log/dmesg.log must NOT silently classify as pass.
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "serial.log").write_text("")
            (art / "dmesg.log").write_text("")
            from harness.schemas import empty_result

            r = empty_result("c1")
            inputs, ctx = _finalize_args(art)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, None)
            self.assertEqual(out["verdict"], "no-dmesg")

    def test_finalize_lkdtm_inverts_pass_when_classifier_quiet(self):
        # LKDTM workload + classifier saw nothing -> kernel-bug (the positive
        # control failed to fire).
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "dmesg.log").write_text("[    0.0] Linux version 6.10\n")
            from harness.schemas import empty_result

            r = empty_result("c1")
            inputs = _inputs(
                art, kvm_required=False, profile={"kind": "bughunt"}, workload_name="lkdtm"
            )
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id,
                artifact_dir=art,
                target=inputs.ssh_target,
                profile=inputs.profile,
            )
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)
            self.assertEqual(out["verdict"], "kernel-bug")

    def test_finalize_lkdtm_skip_when_provoke_missing(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "dmesg.log").write_text("[    0.0] Linux version 6.10\n")
            from harness.schemas import empty_result

            r = empty_result("c1")
            inputs = _inputs(
                art, kvm_required=False, profile={"kind": "bughunt"}, workload_name="lkdtm"
            )
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id,
                artifact_dir=art,
                target=inputs.ssh_target,
                profile=inputs.profile,
            )
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 77)
            self.assertEqual(out["verdict"], "skip:no-lkdtm")


if __name__ == "__main__":
    unittest.main()
