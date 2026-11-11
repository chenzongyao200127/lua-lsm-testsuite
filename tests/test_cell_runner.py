import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness import bundle, cell_runner, hostenv, perf_snapshot, qemu, schemas, ssh
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


# ---------------------------------------------------------------------------
# Moved verbatim from tests/test_round2.py (round-2 dissolution).
# ---------------------------------------------------------------------------


class QemuSpawnOSErrorTests(unittest.TestCase):
    def test_popen_oserror_becomes_qemu_launch_error(self):
        with TemporaryDirectory() as td:
            launcher = Path(td) / "launcher.sh"
            launcher.write_text("#!/bin/sh\nexit 0\n")
            launcher.chmod(0o755)
            with (
                patch("subprocess.Popen", side_effect=OSError("permission denied")),
                self.assertRaises(qemu.QemuLaunchError) as cm,
            ):
                qemu.spawn(launcher, {}, Path(td) / "serial.log")
            self.assertIn("permission denied", str(cm.exception))

    def test_run_cell_finalises_result_on_spawn_oserror(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            launcher = tdp / "launcher.sh"
            launcher.write_text("#!/bin/sh\nexit 0\n")
            launcher.chmod(0o755)
            art = tdp / "art"
            inputs = cell_runner.CellInputs(
                cell_id="oserror_cell",
                profile={"kind": "bughunt"},
                workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
                workload_name="noop",
                launcher=launcher,
                artifact_dir=art,
                ssh_target=ssh.SshTarget(
                    host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")
                ),
                kvm_required=False,
            )
            with patch("subprocess.Popen", side_effect=OSError("bash gone")):
                r = cell_runner.run_cell(
                    inputs,
                    host=hostenv.HostEnv(system="Linux", release="6.10", has_kvm=True),
                )
            self.assertEqual(r["verdict"], "harness-error")
            self.assertTrue((art / "result.json").exists())


class WorkloadFailVerdictTests(unittest.TestCase):
    def _make_ctx(self, art: Path, workload_name: str):
        inputs = cell_runner.CellInputs(
            cell_id="wf_cell",
            profile={"kind": "bughunt"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name=workload_name),
            workload_name=workload_name,
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(
                host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")
            ),
            kvm_required=False,
        )
        ctx = cell_runner.CellContext(
            cell_id=inputs.cell_id,
            artifact_dir=art,
            target=inputs.ssh_target,
            profile=inputs.profile,
        )
        return inputs, ctx

    def _clean_log(self, art: Path):
        (art / "dmesg.log").write_text("[    0.000] Linux version 6.10\n")

    def test_smoke_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "smoke")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "workload-fail")
            self.assertIn("1", out["reason"])

    def test_bench_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "bench")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "workload-fail")

    def test_unixbench_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "unixbench")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 2)
            self.assertEqual(out["verdict"], "workload-fail")

    def test_verify_cleanup_nonzero_rc_emits_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "verify-cleanup")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "workload-fail")

    def test_lkdtm_nonzero_rc_is_not_workload_fail(self):
        # LKDTM rc!=0 must NOT collapse to workload-fail: the LKDTM helper has
        # its own inversion semantics.
        with TemporaryDirectory() as td:
            art = Path(td)
            self._clean_log(art)
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "lkdtm")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertNotEqual(out["verdict"], "workload-fail")

    def test_kernel_bug_outranks_workload_fail(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "dmesg.log").write_text(
                "[    1.0] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30\n"
            )
            r = schemas.empty_result("wf_cell")
            inputs, ctx = self._make_ctx(art, "smoke")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 1)
            self.assertEqual(out["verdict"], "kernel-bug")


class RuntimeBundleTests(unittest.TestCase):
    def _kasan_inputs(self, art: Path, store: bundle.BundleStore, cell_id: str = "kasan_cell"):
        inputs = cell_runner.CellInputs(
            cell_id=cell_id,
            profile={"kind": "bughunt"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
            workload_name="noop",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(
                host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")
            ),
            kvm_required=False,
            bundle_store=store,
            kernel_tree=art / "fake_tree",
            kernel_config_path=art / "fake.config",
            rootfs_image=art / "fake.img",
            decode_script=None,
            policy_paths=(),
        )
        ctx = cell_runner.CellContext(
            cell_id=inputs.cell_id,
            artifact_dir=art,
            target=inputs.ssh_target,
            profile=inputs.profile,
        )
        return inputs, ctx

    def _kasan_log(self, art: Path, lines_before: int = 80, lines_after: int = 80):
        body = []
        for i in range(lines_before):
            body.append(f"[    0.{i:03d}] padding line {i}")
        body.append(
            "[    1.000] =================================================================="
        )
        body.append("[    1.001] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30")
        body.append("[    1.002] Read of size 8 at addr ffff8881020100c0 by task lua/1234")
        for i in range(lines_after):
            body.append(f"[    2.{i:03d}] post line {i}")
        (art / "serial.log").write_text("\n".join(body) + "\n")

    def test_kasan_cell_writes_bundle_with_50_line_slice_and_records_in_result(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "cell"
            art.mkdir(parents=True)
            self._kasan_log(art)
            store = bundle.BundleStore()
            inputs, ctx = self._kasan_inputs(art, store)
            r = schemas.empty_result("kasan_cell")
            r["cmdline"] = "lsm=capability,bpf,lua"
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            self.assertEqual(out["verdict"], "kernel-bug")
            self.assertIn("bundle_dir", out)
            self.assertIn("signature_sha1", out)
            self.assertIn("signature_kind", out)
            bd = Path(out["bundle_dir"])
            # Bundles now live inside the cell's own artifact directory.
            self.assertEqual(bd, art / "bundle")
            self.assertTrue(bd.exists())
            for fname in (
                "kernel.sha",
                ".config",
                "config.diff",
                "cmdline",
                "commands.sh",
                "rootfs.sha256",
                "serial.log",
                "dmesg.txt",
                "decoded.txt",
                "signature",
            ):
                self.assertTrue((bd / fname).exists(), f"bundle missing {fname}")
            self.assertTrue((bd / "policies").is_dir())
            slice_text = (bd / "dmesg.txt").read_text()
            slice_lines = slice_text.splitlines()
            self.assertLessEqual(
                len(slice_lines), 50, "dmesg.txt must be at most 50 lines centered on first hit"
            )
            self.assertTrue(
                any("KASAN" in ln for ln in slice_lines),
                "dmesg.txt slice must contain the first KASAN hit",
            )

    def test_duplicate_signature_yields_dup_of_only(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            store = bundle.BundleStore()
            arts: list[Path] = []
            for cid in ("kasan_a", "kasan_b"):
                art = tdp / cid
                art.mkdir(parents=True)
                self._kasan_log(art)
                arts.append(art)
                inputs, ctx = self._kasan_inputs(art, store, cell_id=cid)
                r = schemas.empty_result(cid)
                r["cmdline"] = "lsm=capability,bpf,lua"
                cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            # Each cell now carries its own bundle dir, sibling to its artifacts.
            payload_dir = arts[0] / "bundle"
            dup_dir = arts[1] / "bundle"
            self.assertTrue(payload_dir.is_dir())
            self.assertTrue(dup_dir.is_dir())
            # First share carries the full payload; duplicate carries only the
            # metadata.json + dup_of.txt pointer back to the first bundle.
            self.assertTrue((payload_dir / "serial.log").exists())
            self.assertFalse((dup_dir / "serial.log").exists())
            self.assertTrue((dup_dir / "dup_of.txt").exists())
            self.assertTrue((dup_dir / "metadata.json").exists())
            # dup_of.txt should resolve back to the first-occurrence bundle.
            rel = (dup_dir / "dup_of.txt").read_text().strip()
            self.assertEqual((dup_dir / rel).resolve(), payload_dir.resolve())

    def test_slice_drawn_from_channel_containing_first_hit(self):
        # AC-6.1 channel-correct slice: when serial.log is clean and the splat
        # is only in dmesg.log, the bundle's dmesg.txt slice must come from
        # dmesg.log (the channel with the hit), not from the serial channel.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "cell"
            art.mkdir(parents=True)
            # Serial is clean and noisy -- a per-aggregate-offset slicer would
            # pick the wrong channel and miss the splat entirely.
            serial_lines = [f"[    0.{i:03d}] boot line {i}" for i in range(200)]
            (art / "serial.log").write_text("\n".join(serial_lines) + "\n")
            dmesg_lines = [f"[    1.{i:03d}] post-boot {i}" for i in range(60)]
            dmesg_lines.append("[    2.000] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30")
            dmesg_lines.append(
                "[    2.001] Read of size 8 at addr ffff8881020100c0 by task lua/1234"
            )
            dmesg_lines.extend(f"[    3.{i:03d}] trail {i}" for i in range(60))
            (art / "dmesg.log").write_text("\n".join(dmesg_lines) + "\n")
            store = bundle.BundleStore()
            inputs, ctx = self._kasan_inputs(art, store)
            r = schemas.empty_result("kasan_cell")
            r["cmdline"] = "lsm=capability,bpf,lua"
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            self.assertEqual(out["verdict"], "kernel-bug")
            bd = Path(out["bundle_dir"])
            slice_text = (bd / "dmesg.txt").read_text()
            self.assertIn(
                "BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30",
                slice_text,
                "slice must come from the channel that contained the hit",
            )
            # Serial-only boot noise should NOT appear in the slice.
            self.assertNotIn("[    0.050] boot line 50", slice_text)
            slice_lines = slice_text.splitlines()
            self.assertLessEqual(len(slice_lines), 50)

    def test_bundle_records_commands_and_resolved_policies(self):
        # AC-6.1: commands.sh must contain the cell's replay commands; policies
        # passed via policy_paths must be copied into bundle/policies/.
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = tdp / "cell"
            art.mkdir(parents=True)
            self._kasan_log(art)
            pol_src = tdp / "policies_src"
            pol_src.mkdir()
            hello = pol_src / "hello.lua"
            hello.write_text("-- hello policy\n")
            store = bundle.BundleStore()
            inputs = cell_runner.CellInputs(
                cell_id="kasan_cell",
                profile={"kind": "bughunt"},
                workload_fn=lambda t, c: cell_runner.WorkloadResult(name="noop"),
                workload_name="noop",
                launcher=Path("/nonexistent/run.sh"),
                artifact_dir=art,
                ssh_target=ssh.SshTarget(
                    host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")
                ),
                kvm_required=False,
                bundle_store=store,
                kernel_tree=art / "fake_tree",
                kernel_config_path=art / "fake.config",
                rootfs_image=art / "fake.img",
                decode_script=None,
                policy_paths=(hello,),
            )
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id,
                artifact_dir=art,
                target=inputs.ssh_target,
                profile=inputs.profile,
            )
            ctx.commands.append("echo replay-step-1")
            ctx.commands.append("cat /sys/kernel/security/lua/lvm_pool_max")
            r = schemas.empty_result("kasan_cell")
            r["cmdline"] = "lsm=capability,bpf,lua"
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)

            bd = Path(out["bundle_dir"])
            cmds_text = (bd / "commands.sh").read_text()
            self.assertIn("echo replay-step-1", cmds_text)
            self.assertIn(
                "cat /sys/kernel/security/lua/lvm_pool_max",
                cmds_text,
            )
            self.assertTrue((bd / "policies" / "hello.lua").exists())
            self.assertEqual(
                (bd / "policies" / "hello.lua").read_text(),
                "-- hello policy\n",
            )


class LkdtmShortCircuitOrderingTests(unittest.TestCase):
    def test_lkdtm_rc77_with_zero_byte_logs_yields_skip_not_no_dmesg(self):
        with TemporaryDirectory() as td:
            art = Path(td)
            (art / "serial.log").write_text("")
            (art / "dmesg.log").write_text("")
            inputs = cell_runner.CellInputs(
                cell_id="lkdtm_cell",
                profile={"kind": "bughunt"},
                workload_fn=lambda t, c: cell_runner.WorkloadResult(name="lkdtm"),
                workload_name="lkdtm",
                launcher=Path("/nonexistent/run.sh"),
                artifact_dir=art,
                ssh_target=ssh.SshTarget(
                    host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null")
                ),
                kvm_required=False,
            )
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id,
                artifact_dir=art,
                target=inputs.ssh_target,
                profile=inputs.profile,
            )
            r = schemas.empty_result("lkdtm_cell")
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 77)
            self.assertEqual(out["verdict"], "skip:no-lkdtm")


class JournalctlAuditTrailTests(unittest.TestCase):
    def _inputs(self, art: Path) -> cell_runner.CellInputs:
        return cell_runner.CellInputs(
            cell_id="journal_cell",
            profile={"kind": "bughunt"},
            workload_fn=lambda t, c: cell_runner.WorkloadResult(name="smoke"),
            workload_name="smoke",
            launcher=Path("/nonexistent/run.sh"),
            artifact_dir=art,
            ssh_target=ssh.SshTarget(
                host="127.0.0.1", port=10025, user="root", key_path=Path("/dev/null")
            ),
            kvm_required=False,
        )

    def test_journalctl_hits_recorded_when_splat_present(self):
        with TemporaryDirectory() as td:
            art = Path(td) / "art"
            art.mkdir()
            (art / "serial.log").write_text("[    0.000] Linux version 6.10\n")
            (art / "dmesg.log").write_text("[    0.001] boot\n")
            (art / "journalctl-kb.txt").write_text(
                "kernel: BUG: KASAN: use-after-free in foo+0x10/0x20\nkernel: Call Trace:\n"
            )
            inputs = self._inputs(art)
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id,
                artifact_dir=art,
                target=inputs.ssh_target,
                profile=inputs.profile,
            )
            r = schemas.empty_result(inputs.cell_id)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)
            # Verdict driven purely by serial+dmesg (no splat there) -> pass.
            self.assertEqual(
                out["verdict"], "pass", "journalctl hits must not flip verdict to kernel-bug"
            )
            # Audit trail captured the journal-only splat.
            self.assertTrue(
                out["journalctl_hits"], "journalctl_hits should be populated when journal has splat"
            )
            self.assertTrue(
                any("KASAN" in h["substring"] for h in out["journalctl_hits"]),
                f"expected KASAN hit, got {out['journalctl_hits']}",
            )
            # And serial/dmesg classification remained clean.
            self.assertEqual(out["classifier_hits"], [])

    def test_journalctl_hits_empty_when_journal_clean(self):
        with TemporaryDirectory() as td:
            art = Path(td) / "art"
            art.mkdir()
            (art / "serial.log").write_text("[    0.000] Linux version 6.10\n")
            (art / "dmesg.log").write_text("[    0.001] boot\n")
            (art / "journalctl-kb.txt").write_text("kernel: nothing to see here\n")
            inputs = self._inputs(art)
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id,
                artifact_dir=art,
                target=inputs.ssh_target,
                profile=inputs.profile,
            )
            r = schemas.empty_result(inputs.cell_id)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)
            self.assertEqual(out["verdict"], "pass")
            self.assertEqual(out["journalctl_hits"], [])

    def test_missing_journalctl_log_is_quiet_no_op(self):
        with TemporaryDirectory() as td:
            art = Path(td) / "art"
            art.mkdir()
            (art / "serial.log").write_text("[    0.000] Linux version 6.10\n")
            (art / "dmesg.log").write_text("[    0.001] boot\n")
            # Deliberately no journalctl-kb.txt -- a teardown without the
            # follower must not raise or pollute result.
            inputs = self._inputs(art)
            ctx = cell_runner.CellContext(
                cell_id=inputs.cell_id,
                artifact_dir=art,
                target=inputs.ssh_target,
                profile=inputs.profile,
            )
            r = schemas.empty_result(inputs.cell_id)
            out = cell_runner._classify_and_finalize(r, art, inputs, ctx, 0)
            self.assertEqual(out["verdict"], "pass")
            self.assertEqual(out["journalctl_hits"], [])
