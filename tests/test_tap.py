import unittest

from harness import tap


class TapTests(unittest.TestCase):
    def test_emit_tap_basic(self):
        matrix = {
            "cells": [
                {"cell_id": "a-pass", "verdict": "pass"},
                {"cell_id": "b-fail", "verdict": "kernel-bug"},
                {"cell_id": "c-skip", "verdict": "skip:no-kvm"},
            ]
        }
        out = tap.emit_tap(matrix)
        self.assertIn("TAP version 13", out)
        self.assertIn("1..3", out)
        self.assertIn("ok 1 - a-pass\n", out)
        self.assertIn("not ok 2 - b-fail\n", out)
        self.assertIn("    # verdict: kernel-bug\n", out)
        self.assertIn("ok 3 - c-skip # SKIP skip:no-kvm\n", out)

    def test_emit_tap_sorts_by_cell_id(self):
        matrix = {
            "cells": [
                {"cell_id": "z", "verdict": "pass"},
                {"cell_id": "a", "verdict": "pass"},
                {"cell_id": "m", "verdict": "pass"},
            ]
        }
        out = tap.emit_tap(matrix)
        idx_a = out.index("- a\n")
        idx_m = out.index("- m\n")
        idx_z = out.index("- z\n")
        self.assertLess(idx_a, idx_m)
        self.assertLess(idx_m, idx_z)

    def test_unrun_cell_is_not_ok(self):
        matrix = {"cells": [{"cell_id": "x", "verdict": None}]}
        out = tap.emit_tap(matrix)
        self.assertIn("not ok 1 - x\n", out)
        self.assertIn("# verdict: no-verdict\n", out)

    def test_stats_unavailable_is_skip(self):
        # AC: skip:stats-unavailable must be classified as SKIP, not FAIL.
        matrix = {"cells": [{"cell_id": "perf-cell", "verdict": "skip:stats-unavailable"}]}
        out = tap.emit_tap(matrix)
        self.assertIn("ok 1 - perf-cell # SKIP skip:stats-unavailable\n", out)

    def test_empty_matrix_yields_zero_plan(self):
        out = tap.emit_tap({"cells": []})
        self.assertIn("1..0", out)

    # AC-8 pinning tests: plan line LAST, header FIRST.

    def test_plan_line_is_last_with_mixed_pass_skip(self):
        matrix = {
            "cells": [
                {"cell_id": "a", "verdict": "pass"},
                {"cell_id": "b", "verdict": "skip:no-kvm"},
                {"cell_id": "c", "verdict": "pass"},
            ]
        }
        out = tap.emit_tap(matrix)
        lines = out.strip().split("\n")
        self.assertEqual(lines[0], "TAP version 13", "TAP header must be the first line")
        self.assertEqual(lines[-1], "1..3", "plan line must be the last line")
        # All test-point lines fall between header and plan.
        for inner in lines[1:-1]:
            self.assertFalse(inner.startswith("TAP version"))
            self.assertFalse(inner.startswith("1.."))

    def test_plan_line_is_last_with_all_skip(self):
        matrix = {
            "cells": [
                {"cell_id": "a", "verdict": "skip:no-kvm"},
                {"cell_id": "b", "verdict": "skip:stats-unavailable"},
            ]
        }
        out = tap.emit_tap(matrix)
        lines = out.strip().split("\n")
        self.assertEqual(lines[0], "TAP version 13")
        self.assertEqual(lines[-1], "1..2")

    def test_plan_line_is_last_with_failure(self):
        matrix = {
            "cells": [
                {"cell_id": "a", "verdict": "pass"},
                {"cell_id": "b", "verdict": "kernel-bug"},
            ]
        }
        out = tap.emit_tap(matrix)
        lines = out.strip().split("\n")
        self.assertEqual(lines[0], "TAP version 13")
        self.assertEqual(lines[-1], "1..2")
        # The not ok line must appear before the plan.
        not_ok_idx = next(i for i, line in enumerate(lines) if line.startswith("not ok"))
        plan_idx = lines.index("1..2")
        self.assertLess(not_ok_idx, plan_idx)


class TapDefaultMatrixOutputTests(unittest.TestCase):
    """Default non-TAP CLI matrix output (without --tap) must NOT contain the
    TAP version header or a plan line; the harness only emits TAP when the
    caller explicitly opts in."""

    def test_default_matrix_stdout_has_no_tap_header(self):
        import json
        from contextlib import redirect_stdout
        from io import StringIO
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        from harness import __main__ as cli
        from harness import cell_runner
        from harness import matrix as matrix_mod

        def _stub(inputs, host=None):
            inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
            res = {
                "schema_version": 1,
                "cell_id": inputs.cell_id,
                "verdict": "pass",
                "started_at": None,
                "finished_at": None,
            }
            (inputs.artifact_dir / "result.json").write_text(json.dumps(res))
            return res

        with TemporaryDirectory() as td:
            tdp = Path(td)
            cfg = tdp / "tiny.json"
            cfg.write_text(
                json.dumps(
                    {
                        "name": "t",
                        "axes": {"x": [1]},
                        "defaults": {"kvm_required": False},
                    }
                )
            )
            buf = StringIO()
            with (
                patch.object(cell_runner, "run_cell", side_effect=_stub),
                patch.object(matrix_mod, "assert_share_dir", lambda *_args, **_kw: None),
                patch.object(cli, "_enforce_supported_host", lambda: None),
                redirect_stdout(buf),
            ):
                rc = cli.main(
                    [
                        "matrix",
                        "--config",
                        str(cfg),
                        "--ssh-key",
                        "/dev/null",
                        "--launcher",
                        "/nonexistent/run.sh",
                        "--runs-root",
                        str(tdp / "runs"),
                        "--port-base",
                        "20000",
                    ]
                )
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertNotIn("TAP version 13", out)
            self.assertNotIn("1..1", out)


if __name__ == "__main__":
    unittest.main()
