import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness import matrix


class ExpandTests(unittest.TestCase):
    def test_expand_cartesian_product(self):
        plan = matrix.expand({
            "name": "demo",
            "axes": {
                "kind": ["perf", "bughunt"],
                "pool_max": [4, 16],
            },
        })
        self.assertEqual(len(plan), 4)
        kinds = sorted({c.profile["kind"] for c in plan})
        self.assertEqual(kinds, ["bughunt", "perf"])

    def test_expand_with_exclude(self):
        plan = matrix.expand({
            "name": "demo",
            "axes": {"kind": ["perf", "bughunt"], "pool_max": [4, 16]},
            "exclude": [{"kind": "perf", "pool_max": 4}],
        })
        self.assertEqual(len(plan), 3)
        for c in plan:
            self.assertFalse(c.profile["kind"] == "perf" and c.profile["pool_max"] == 4)

    def test_expand_no_axes_emits_default_cell(self):
        plan = matrix.expand({"name": "demo", "defaults": {"kvm_required": True}})
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0].profile["kvm_required"], True)

    def test_expand_workload_default_propagates(self):
        plan = matrix.expand({
            "name": "demo",
            "workload": "bench",
            "axes": {"k": [1, 2]},
        })
        self.assertTrue(all(c.workload == "bench" for c in plan))

    def test_smoke_matrix_has_32_cells(self):
        # DEC-5 hard requirement: minimal smoke matrix is exactly 32 cells.
        # Use the JSON variant when PyYAML is unavailable; both must agree.
        configs = Path(__file__).resolve().parent.parent / "configs"
        path = configs / "smoke.json"
        plan = matrix.plan_from_file(path)
        self.assertEqual(len(plan.cells), 32, f"smoke matrix expanded to {len(plan.cells)} cells, expected 32")

    def test_smoke_matrix_exposes_dec5_axes(self):
        """DEC-5: the default smoke sweep is policy x lvm_pool_max x
        kconfig_profile x workload, with the documented value sets."""
        configs = Path(__file__).resolve().parent.parent / "configs"
        plan = matrix.plan_from_file(configs / "smoke.json")
        policies = sorted({c.profile["policy"] for c in plan.cells})
        pools = sorted({c.profile["lvm_pool_max"] for c in plan.cells})
        profiles = sorted({c.profile["kconfig_profile"] for c in plan.cells})
        workloads_seen = sorted({c.profile["workload"] for c in plan.cells})
        self.assertEqual(policies, ["denyfile", "exectl", "hello", "pindown"])
        self.assertEqual(pools, [0, 32])
        self.assertEqual(profiles, ["full", "standard"])
        self.assertEqual(workloads_seen, ["bench-short", "smoke"])

    def test_perf_matrix_carries_policy_default(self):
        """Round 5 / AC-5.1: every cell expanded from configs/perf.yaml
        must carry a non-empty `policy` profile knob so the UnixBench
        workload's register step has a real policy file to install."""
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed; skip perf.yaml policy default check")
        configs = Path(__file__).resolve().parent.parent / "configs"
        plan = matrix.plan_from_file(configs / "perf.yaml")
        self.assertGreater(len(plan.cells), 0, "perf matrix expanded to zero cells")
        for c in plan.cells:
            self.assertIn("policy", c.profile,
                          f"perf cell {c.cell_id} is missing a `policy` knob")
            self.assertTrue(c.profile["policy"],
                            f"perf cell {c.cell_id} has empty policy")

    def test_smoke_matrix_yaml_and_json_agree(self):
        """Both shipped smoke configs must expand to the same 32 cell ids so
        the two formats stay in lock-step for environments without PyYAML."""
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed; skip YAML/JSON cross-check")
        configs = Path(__file__).resolve().parent.parent / "configs"
        ids_yaml = sorted(c.cell_id for c in matrix.plan_from_file(configs / "smoke.yaml").cells)
        ids_json = sorted(c.cell_id for c in matrix.plan_from_file(configs / "smoke.json").cells)
        self.assertEqual(ids_yaml, ids_json)


class ExecutorTests(unittest.TestCase):
    def test_run_matrix_aggregates_totals_and_writes_json(self):
        plan = matrix.MatrixPlan(name="demo", cells=[
            matrix.CellSpec(cell_id="c1", profile={"k": 1}, workload="smoke"),
            matrix.CellSpec(cell_id="c2", profile={"k": 2}, workload="smoke"),
            matrix.CellSpec(cell_id="c3", profile={"k": 3}, workload="smoke"),
        ])

        verdicts = {"c1": "pass", "c2": "kernel-bug", "c3": "skip:no-kvm"}
        seen_ports: list[int] = []

        def fake_runner(cell, artifact_dir, port):
            seen_ports.append(port)
            return {
                "schema_version": 1,
                "cell_id": cell.cell_id,
                "verdict": verdicts[cell.cell_id],
                "started_at": "2026-05-27T00:00:00+00:00",
                "finished_at": "2026-05-27T00:00:01+00:00",
            }

        with TemporaryDirectory() as td:
            opts = matrix.ExecutorOpts(parallel=2, runs_root=Path(td), port_base=10100)
            m = matrix.run_matrix(plan, opts, fake_runner)
            self.assertEqual(m["totals"]["passed"], 1)
            self.assertEqual(m["totals"]["failed"], 1)
            self.assertEqual(m["totals"]["skipped"], 1)
            # The matrix.json is written under runs_root/<utc-id>/matrix.json.
            json_files = list(Path(td).rglob("matrix.json"))
            self.assertEqual(len(json_files), 1)
            on_disk = json.loads(json_files[0].read_text())
            self.assertEqual(on_disk["totals"]["passed"], 1)
            # Port allocator handed out distinct ports starting at port_base.
            self.assertEqual(sorted(seen_ports), [10100, 10101, 10102])


class PortAllocTests(unittest.TestCase):
    def test_allocate_ports_default_base(self):
        ports = matrix.allocate_ports(3)
        self.assertEqual(ports, [10023, 10024, 10025])

    def test_allocate_ports_custom_base(self):
        self.assertEqual(matrix.allocate_ports(2, base=12000), [12000, 12001])

    def test_allocate_ports_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            matrix.allocate_ports(10, base=65530)


class ShareDirTests(unittest.TestCase):
    def test_share_dir_refuses_missing_lua_lsm_tools(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "kernel" / "linux").mkdir(parents=True)
            with self.assertRaises(matrix.ShareDirError):
                matrix.assert_share_dir(tdp)

    def test_share_dir_accepts_valid_workspace(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "lua-lsm-tools").mkdir(parents=True)
            (tdp / "kernel" / "linux").mkdir(parents=True)
            matrix.assert_share_dir(tdp)  # no exception

    def test_share_dir_requirement_is_workload_aware(self):
        self.assertEqual(
            matrix.required_share_entries(["functional"]),
            ("lua-lsm-testsuite",),
        )
        self.assertEqual(
            matrix.required_share_entries(["functional", "smoke"]),
            matrix.REQUIRED_SHARE_ENTRIES,
        )


if __name__ == "__main__":
    unittest.main()
