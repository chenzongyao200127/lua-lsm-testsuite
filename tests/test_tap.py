"""Unit tests for TAP v13 emission (harness.tap)."""

import json

from harness import __main__ as cli
from harness import cell_runner, tap
from harness import matrix as matrix_mod
from harness.cli import common as cli_common


def test_emit_tap_basic():
    matrix = {
        "cells": [
            {"cell_id": "a-pass", "verdict": "pass"},
            {"cell_id": "b-fail", "verdict": "kernel-bug"},
            {"cell_id": "c-skip", "verdict": "skip:no-kvm"},
        ]
    }
    out = tap.emit_tap(matrix)
    assert "TAP version 13" in out
    assert "1..3" in out
    assert "ok 1 - a-pass\n" in out
    assert "not ok 2 - b-fail\n" in out
    assert "    # verdict: kernel-bug\n" in out
    assert "ok 3 - c-skip # SKIP skip:no-kvm\n" in out


def test_emit_tap_sorts_by_cell_id():
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
    assert idx_a < idx_m
    assert idx_m < idx_z


def test_unrun_cell_is_not_ok():
    matrix = {"cells": [{"cell_id": "x", "verdict": None}]}
    out = tap.emit_tap(matrix)
    assert "not ok 1 - x\n" in out
    assert "# verdict: no-verdict\n" in out


def test_stats_unavailable_is_skip():
    # AC: skip:stats-unavailable must be classified as SKIP, not FAIL.
    matrix = {"cells": [{"cell_id": "perf-cell", "verdict": "skip:stats-unavailable"}]}
    out = tap.emit_tap(matrix)
    assert "ok 1 - perf-cell # SKIP skip:stats-unavailable\n" in out


def test_empty_matrix_yields_zero_plan():
    out = tap.emit_tap({"cells": []})
    assert "1..0" in out


# AC-8 pinning tests: plan line LAST, header FIRST.


def test_plan_line_is_last_with_mixed_pass_skip():
    matrix = {
        "cells": [
            {"cell_id": "a", "verdict": "pass"},
            {"cell_id": "b", "verdict": "skip:no-kvm"},
            {"cell_id": "c", "verdict": "pass"},
        ]
    }
    out = tap.emit_tap(matrix)
    lines = out.strip().split("\n")
    assert lines[0] == "TAP version 13", "TAP header must be the first line"
    assert lines[-1] == "1..3", "plan line must be the last line"
    # All test-point lines fall between header and plan.
    for inner in lines[1:-1]:
        assert not inner.startswith("TAP version")
        assert not inner.startswith("1..")


def test_plan_line_is_last_with_all_skip():
    matrix = {
        "cells": [
            {"cell_id": "a", "verdict": "skip:no-kvm"},
            {"cell_id": "b", "verdict": "skip:stats-unavailable"},
        ]
    }
    out = tap.emit_tap(matrix)
    lines = out.strip().split("\n")
    assert lines[0] == "TAP version 13"
    assert lines[-1] == "1..2"


def test_plan_line_is_last_with_failure():
    matrix = {
        "cells": [
            {"cell_id": "a", "verdict": "pass"},
            {"cell_id": "b", "verdict": "kernel-bug"},
        ]
    }
    out = tap.emit_tap(matrix)
    lines = out.strip().split("\n")
    assert lines[0] == "TAP version 13"
    assert lines[-1] == "1..2"
    # The not ok line must appear before the plan.
    not_ok_idx = next(i for i, line in enumerate(lines) if line.startswith("not ok"))
    plan_idx = lines.index("1..2")
    assert not_ok_idx < plan_idx


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


def test_default_matrix_stdout_has_no_tap_header(tmp_path, monkeypatch, capsys):
    """Default non-TAP CLI matrix output (without --tap) must NOT contain the
    TAP version header or a plan line; the harness only emits TAP when the
    caller explicitly opts in."""
    cfg = tmp_path / "tiny.json"
    cfg.write_text(
        json.dumps(
            {
                "name": "t",
                "axes": {"x": [1]},
                "defaults": {"kvm_required": False},
            }
        )
    )
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
            "20000",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "TAP version 13" not in out
    assert "1..1" not in out
