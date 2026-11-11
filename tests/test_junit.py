"""Unit tests for JUnit XML emission (harness.junit)."""

import json
from xml.etree import ElementTree as ET

from harness import __main__ as cli
from harness import cell_runner, junit
from harness import matrix as matrix_mod
from harness.cli import common as cli_common


def _parse(xml: str) -> ET.Element:
    """Parse emitted XML, skipping the <?xml ...?> declaration."""
    return ET.fromstring(xml.split("?>", 1)[1])


def test_mixed_verdict_matrix_counts_and_per_cell_elements():
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
    root = _parse(junit.emit_junit(matrix))
    # Walk element shape rather than string-matching.
    assert root.tag == "testsuites"
    assert root.attrib["tests"] == "4"
    assert root.attrib["failures"] == "1"
    assert root.attrib["skipped"] == "2"
    assert root.attrib["name"] == "smoke"

    suite = root.find("testsuite")
    assert suite is not None
    assert suite.attrib["tests"] == "4"
    assert suite.attrib["failures"] == "1"
    assert suite.attrib["skipped"] == "2"

    cases = {c.attrib["name"]: c for c in suite.findall("testcase")}
    assert set(cases) == {"a-pass", "b-fail", "c-skip", "d-stats-skip"}
    # pass cell: bare, no children.
    assert len(list(cases["a-pass"])) == 0
    # fail cell: <failure type="kernel-bug" message="...">.
    fail_el = cases["b-fail"].find("failure")
    assert fail_el is not None
    assert fail_el.attrib["type"] == "kernel-bug"
    assert "kernel-bug" in fail_el.attrib["message"]
    # skip cells: <skipped message="<verdict>">; verdicts preserved verbatim.
    sk1 = cases["c-skip"].find("skipped")
    assert sk1 is not None
    assert sk1.attrib["message"] == "skip:no-kvm"
    sk2 = cases["d-stats-skip"].find("skipped")
    assert sk2 is not None
    assert sk2.attrib["message"] == "skip:stats-unavailable"


def test_unrun_cell_classifies_as_failure():
    matrix = {"name": "x", "cells": [{"cell_id": "z", "verdict": None}]}
    root = _parse(junit.emit_junit(matrix))
    assert root.attrib["failures"] == "1"
    case = root.find("testsuite/testcase")
    fail_el = case.find("failure")
    assert fail_el is not None
    assert fail_el.attrib["type"] == "no-verdict"


def test_cases_sorted_by_cell_id():
    matrix = {
        "name": "x",
        "cells": [
            {"cell_id": "z", "verdict": "pass"},
            {"cell_id": "a", "verdict": "pass"},
            {"cell_id": "m", "verdict": "pass"},
        ],
    }
    root = _parse(junit.emit_junit(matrix))
    names = [c.attrib["name"] for c in root.findall("testsuite/testcase")]
    assert names == ["a", "m", "z"]


def test_empty_matrix_yields_zero_counts():
    root = _parse(junit.emit_junit({"name": "x", "cells": []}))
    assert root.attrib["tests"] == "0"
    assert root.attrib["failures"] == "0"
    assert root.attrib["skipped"] == "0"
    assert len(root.findall("testsuite/testcase")) == 0


def test_xml_has_declaration_and_is_well_formed():
    xml = junit.emit_junit(
        {
            "name": "x",
            "cells": [
                {"cell_id": "a", "verdict": "pass"},
            ],
        }
    )
    assert xml.startswith("<?xml")
    # Must parse without raising.
    _parse(xml)


def _stub_run_cell(inputs, host=None):
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


def test_matrix_cli_writes_junit_file(tmp_path, monkeypatch, capsys):
    """End-to-end: `harness matrix --junit <path>` must write a JUnit XML
    file containing one <testcase> per cell."""
    cfg = tmp_path / "tiny.json"
    cfg.write_text(
        json.dumps(
            {
                "name": "tiny",
                "axes": {"x": [1, 2]},
                "defaults": {"kvm_required": False},
            }
        )
    )
    junit_path = tmp_path / "out" / "junit.xml"
    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    monkeypatch.setattr(matrix_mod, "assert_share_dir", lambda *_args, **_kw: None)
    monkeypatch.setattr(cli_common, "enforce_supported_host", lambda: None)

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
            str(tmp_path / "runs"),
            "--port-base",
            "21000",
            "--junit",
            str(junit_path),
        ]
    )
    assert rc == 0
    assert junit_path.exists(), "matrix --junit must create the file (parent mkdir)"
    root = _parse(junit_path.read_text())
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "0"
    assert root.attrib["skipped"] == "0"
