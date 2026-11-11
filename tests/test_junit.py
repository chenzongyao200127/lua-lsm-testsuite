import unittest
from xml.etree import ElementTree as ET

from harness import junit


class JUnitEmitTests(unittest.TestCase):
    def test_mixed_verdict_matrix_counts_and_per_cell_elements(self):
        """Pinning test for the JUnit emitter: mixed-verdict matrix must
        yield correct testsuites/testsuite counts AND the right per-cell
        <failure> / <skipped> elements (pass cells stay bare)."""
        matrix = {
            "name": "smoke",
            "cells": [
                {"cell_id": "a-pass", "verdict": "pass"},
                {"cell_id": "b-fail", "verdict": "kernel-bug"},
                {"cell_id": "c-skip", "verdict": "skip:no-kvm"},
                {"cell_id": "d-stats-skip", "verdict": "skip:stats-unavailable"},
            ],
        }
        xml = junit.emit_junit(matrix)
        # Parse and walk; relying on element shape rather than string match.
        root = ET.fromstring(xml.split("?>", 1)[1])
        self.assertEqual(root.tag, "testsuites")
        self.assertEqual(root.attrib["tests"], "4")
        self.assertEqual(root.attrib["failures"], "1")
        self.assertEqual(root.attrib["skipped"], "2")
        self.assertEqual(root.attrib["name"], "smoke")

        suite = root.find("testsuite")
        self.assertIsNotNone(suite)
        self.assertEqual(suite.attrib["tests"], "4")
        self.assertEqual(suite.attrib["failures"], "1")
        self.assertEqual(suite.attrib["skipped"], "2")

        cases = {c.attrib["name"]: c for c in suite.findall("testcase")}
        self.assertEqual(set(cases), {"a-pass", "b-fail", "c-skip", "d-stats-skip"})
        # pass cell: bare, no children.
        self.assertEqual(len(list(cases["a-pass"])), 0)
        # fail cell: <failure type="kernel-bug" message="...">.
        fail_el = cases["b-fail"].find("failure")
        self.assertIsNotNone(fail_el)
        self.assertEqual(fail_el.attrib["type"], "kernel-bug")
        self.assertIn("kernel-bug", fail_el.attrib["message"])
        # skip cells: <skipped message="<verdict>">; verdicts preserved verbatim.
        sk1 = cases["c-skip"].find("skipped")
        self.assertIsNotNone(sk1)
        self.assertEqual(sk1.attrib["message"], "skip:no-kvm")
        sk2 = cases["d-stats-skip"].find("skipped")
        self.assertIsNotNone(sk2)
        self.assertEqual(sk2.attrib["message"], "skip:stats-unavailable")

    def test_unrun_cell_classifies_as_failure(self):
        matrix = {"name": "x", "cells": [{"cell_id": "z", "verdict": None}]}
        xml = junit.emit_junit(matrix)
        root = ET.fromstring(xml.split("?>", 1)[1])
        self.assertEqual(root.attrib["failures"], "1")
        case = root.find("testsuite/testcase")
        fail_el = case.find("failure")
        self.assertIsNotNone(fail_el)
        self.assertEqual(fail_el.attrib["type"], "no-verdict")

    def test_cases_sorted_by_cell_id(self):
        matrix = {
            "name": "x",
            "cells": [
                {"cell_id": "z", "verdict": "pass"},
                {"cell_id": "a", "verdict": "pass"},
                {"cell_id": "m", "verdict": "pass"},
            ],
        }
        xml = junit.emit_junit(matrix)
        root = ET.fromstring(xml.split("?>", 1)[1])
        names = [c.attrib["name"] for c in root.findall("testsuite/testcase")]
        self.assertEqual(names, ["a", "m", "z"])

    def test_empty_matrix_yields_zero_counts(self):
        xml = junit.emit_junit({"name": "x", "cells": []})
        root = ET.fromstring(xml.split("?>", 1)[1])
        self.assertEqual(root.attrib["tests"], "0")
        self.assertEqual(root.attrib["failures"], "0")
        self.assertEqual(root.attrib["skipped"], "0")
        self.assertEqual(len(root.findall("testsuite/testcase")), 0)

    def test_xml_has_declaration_and_is_well_formed(self):
        xml = junit.emit_junit(
            {
                "name": "x",
                "cells": [
                    {"cell_id": "a", "verdict": "pass"},
                ],
            }
        )
        self.assertTrue(xml.startswith("<?xml"))
        # Must parse without raising.
        ET.fromstring(xml.split("?>", 1)[1])


class JUnitCliWritesFileTests(unittest.TestCase):
    """End-to-end: `harness matrix --junit <path>` must write a JUnit XML
    file containing one <testcase> per cell."""

    def test_matrix_cli_writes_junit_file(self):
        import json
        from contextlib import redirect_stdout
        from io import StringIO
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        from harness import __main__ as cli
        from harness import cell_runner
        from harness import matrix as matrix_mod
        from harness.cli import common as cli_common

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
                        "name": "tiny",
                        "axes": {"x": [1, 2]},
                        "defaults": {"kvm_required": False},
                    }
                )
            )
            junit_path = tdp / "out" / "junit.xml"
            buf = StringIO()
            with (
                patch.object(cell_runner, "run_cell", side_effect=_stub),
                patch.object(matrix_mod, "assert_share_dir", lambda *_args, **_kw: None),
                patch.object(cli_common, "enforce_supported_host", lambda: None),
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
                        "21000",
                        "--junit",
                        str(junit_path),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(
                junit_path.exists(), "matrix --junit must create the file (parent mkdir)"
            )
            xml = junit_path.read_text()
            root = ET.fromstring(xml.split("?>", 1)[1])
            self.assertEqual(root.attrib["tests"], "2")
            self.assertEqual(root.attrib["failures"], "0")
            self.assertEqual(root.attrib["skipped"], "0")


if __name__ == "__main__":
    unittest.main()
