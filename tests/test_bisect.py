"""Unit tests for bisect exit-code mapping and bisect-run cell mode (harness.bisect)."""

import json
from pathlib import Path

import pytest
from harness import __main__ as cli
from harness import bisect, cell_runner
from harness import bisect as bisect_mod


def test_all_pass_is_zero():
    assert (
        bisect.exit_code_from_totals(
            {"executed": 4, "passed": 4, "failed": 0, "skipped": 0, "aborted": 0}
        )
        == 0
    )


def test_any_fail_is_one():
    assert (
        bisect.exit_code_from_totals(
            {"executed": 4, "passed": 3, "failed": 1, "skipped": 0, "aborted": 0}
        )
        == 1
    )


def test_aborted_treated_as_fail():
    assert (
        bisect.exit_code_from_totals(
            {"executed": 4, "passed": 3, "failed": 0, "skipped": 0, "aborted": 1}
        )
        == 1
    )


def test_all_skip_is_125():
    assert (
        bisect.exit_code_from_totals(
            {"executed": 4, "passed": 0, "failed": 0, "skipped": 4, "aborted": 0}
        )
        == 125
    )


def test_no_cells_is_128():
    assert bisect.exit_code_from_totals({"executed": 0}) == 128


def test_partial_skip_with_pass_is_zero():
    # Non-trivial signal: 3 cells passed and 1 skipped -> bisect treats commit as good.
    assert (
        bisect.exit_code_from_totals(
            {"executed": 4, "passed": 3, "failed": 0, "skipped": 1, "aborted": 0}
        )
        == 0
    )


def test_exit_code_from_matrix_dict():
    m = {"totals": {"executed": 1, "passed": 1, "failed": 0, "skipped": 0, "aborted": 0}}
    assert bisect.exit_code_from_matrix(m) == 0


def test_exit_code_from_matrix_missing_totals():
    assert bisect.exit_code_from_matrix({}) == 128


# ---------------------------------------------------------------------------
# Moved from tests/test_round2.py (round-2 dissolution).
# ---------------------------------------------------------------------------


def _write_cell(tdp: Path, profile: dict) -> Path:
    p = tdp / "cell.json"
    p.write_text(json.dumps(profile))
    return p


def _common_args(tdp: Path, cell_path: Path, extra: list[str] | None = None) -> list[str]:
    args = [
        "bisect-run",
        "--cell",
        str(cell_path),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/run.sh",
        "--runs-root",
        str(tdp / "runs"),
        "--port-base",
        "23000",
    ]
    if extra:
        args.extend(extra)
    return args


def test_clean_cell_returns_ksft_pass(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    cell = _write_cell(
        tdp,
        {
            "workload": "smoke",
            "kind": "bughunt",
        },
    )

    def _stub_run_cell(inputs, host=None):
        inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
        result = {
            "schema_version": 1,
            "cell_id": inputs.cell_id,
            "verdict": "pass",
        }
        (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
        return result

    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    rc = cli.main(_common_args(tdp, cell))
    assert rc == bisect_mod.KSFT_PASS


def test_classifier_hit_returns_ksft_fail(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    cell = _write_cell(
        tdp,
        {
            "workload": "smoke",
            "kind": "bughunt",
        },
    )

    def _stub_run_cell(inputs, host=None):
        inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
        result = {
            "schema_version": 1,
            "cell_id": inputs.cell_id,
            "verdict": "kernel-bug",
        }
        (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
        return result

    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    rc = cli.main(_common_args(tdp, cell))
    assert rc == bisect_mod.KSFT_FAIL


def test_build_helper_failure_returns_ksft_skip(tmp_path, linux_host):
    # When --build-kernel is set and the helper exits non-zero, the
    # commit cannot be tested. Bisect must skip (125), not fail (1).
    tdp = tmp_path
    cell = _write_cell(
        tdp,
        {
            "workload": "smoke",
            "kind": "bughunt",
            "kconfig_profile": "standard",
        },
    )
    debug_kernel = tdp / "tools"
    debug_kernel.mkdir()
    helper = debug_kernel / "enable-debug-kconfig.sh"
    helper.write_text("#!/bin/sh\nexit 1\n")
    helper.chmod(0o755)
    kernel_tree = tdp / "linux"
    kernel_tree.mkdir()

    args = _common_args(
        tdp,
        cell,
        extra=[
            "--debug-kernel",
            str(debug_kernel),
            "--kernel-tree",
            str(kernel_tree),
            "--build-kernel",
        ],
    )
    rc = cli.main(args)
    assert rc == bisect_mod.KSFT_SKIP, "build-helper failure must be bisect-skip (125), not fail"


def test_image_not_warm_verdict_returns_ksft_skip(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    cell = _write_cell(
        tdp,
        {
            "workload": "bench",
            "kind": "perf",
        },
    )

    def _stub_run_cell(inputs, host=None):
        inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
        result = {
            "schema_version": 1,
            "cell_id": inputs.cell_id,
            "verdict": "skip:image-not-warm",
        }
        (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
        return result

    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    rc = cli.main(_common_args(tdp, cell))
    assert rc == bisect_mod.KSFT_SKIP


def test_build_fail_verdict_returns_ksft_skip(tmp_path, monkeypatch, linux_host):
    # build-fail is FAIL_VERDICTS for TAP but UNTESTABLE for bisect.
    tdp = tmp_path
    cell = _write_cell(
        tdp,
        {
            "workload": "smoke",
            "kind": "bughunt",
        },
    )

    def _stub_run_cell(inputs, host=None):
        inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
        result = {
            "schema_version": 1,
            "cell_id": inputs.cell_id,
            "verdict": "build-fail",
        }
        (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
        return result

    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    rc = cli.main(_common_args(tdp, cell))
    assert rc == bisect_mod.KSFT_SKIP


def test_bundle_write_failure_returns_ksft_abort(tmp_path, monkeypatch, linux_host):
    # When the runner finished but bundle emission threw, result["bundle_error"]
    # is set. Bisect must abort (128) so the bisect halts rather than blaming
    # the commit on a harness-side packaging failure.
    tdp = tmp_path
    cell = _write_cell(
        tdp,
        {
            "workload": "smoke",
            "kind": "bughunt",
        },
    )

    def _stub_run_cell(inputs, host=None):
        inputs.artifact_dir.mkdir(parents=True, exist_ok=True)
        # The kernel produced a real hit (so the bundle attempt fired)
        # but bundle packaging blew up.
        result = {
            "schema_version": 1,
            "cell_id": inputs.cell_id,
            "verdict": "kernel-bug",
            "bundle_error": "OSError: disk full",
        }
        (inputs.artifact_dir / "result.json").write_text(json.dumps(result))
        return result

    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    rc = cli.main(_common_args(tdp, cell))
    assert rc == bisect_mod.KSFT_ABORT, "bundle_error must abort bisect (128)"


def test_run_cell_raises_returns_ksft_abort(tmp_path, monkeypatch, linux_host):
    tdp = tmp_path
    cell = _write_cell(
        tdp,
        {
            "workload": "smoke",
            "kind": "bughunt",
        },
    )

    def _stub_run_cell(inputs, host=None):
        raise RuntimeError("harness internal blew up")

    monkeypatch.setattr(cell_runner, "run_cell", _stub_run_cell)
    rc = cli.main(_common_args(tdp, cell))
    assert rc == bisect_mod.KSFT_ABORT


def test_cell_and_config_are_mutually_exclusive(tmp_path, linux_host):
    tdp = tmp_path
    cell = _write_cell(tdp, {"workload": "smoke"})
    mat = tdp / "m.json"
    mat.write_text(json.dumps({"name": "m", "defaults": {"workload": "smoke"}}))
    args = [
        "bisect-run",
        "--cell",
        str(cell),
        "--config",
        str(mat),
        "--ssh-key",
        "/dev/null",
        "--launcher",
        "/nonexistent/run.sh",
        "--runs-root",
        str(tdp / "runs"),
    ]
    with pytest.raises(SystemExit) as ctx:
        cli.main(args)
    assert ctx.value.code != 0, "argparse must reject --cell with --config"


# Pure mapping tests over bisect.exit_code_from_cell_result().


def test_pass():
    assert bisect_mod.exit_code_from_cell_result({"verdict": "pass"}) == bisect_mod.KSFT_PASS


def test_kernel_bug_is_bad():
    assert bisect_mod.exit_code_from_cell_result({"verdict": "kernel-bug"}) == bisect_mod.KSFT_FAIL


def test_workload_fail_is_bad():
    assert bisect_mod.exit_code_from_cell_result({"verdict": "workload-fail"}) == (
        bisect_mod.KSFT_FAIL
    )


def test_build_fail_is_untestable():
    assert bisect_mod.exit_code_from_cell_result({"verdict": "build-fail"}) == bisect_mod.KSFT_SKIP


def test_boot_timeout_is_untestable():
    assert bisect_mod.exit_code_from_cell_result({"verdict": "boot-timeout"}) == (
        bisect_mod.KSFT_SKIP
    )


@pytest.mark.parametrize(
    "verdict",
    [
        "skip:no-kvm",
        "skip:stats-unavailable",
        "skip:image-not-warm",
        "skip:no-lkdtm",
        "skip:fixture-missing",
    ],
)
def test_skip_verdicts_are_untestable(verdict):
    assert bisect_mod.exit_code_from_cell_result({"verdict": verdict}) == bisect_mod.KSFT_SKIP, (
        f"{verdict} should map to 125"
    )


@pytest.mark.parametrize("verdict", ["harness-error", "aborted", "no-dmesg"])
def test_harness_error_verdicts_abort(verdict):
    assert bisect_mod.exit_code_from_cell_result({"verdict": verdict}) == bisect_mod.KSFT_ABORT, (
        f"{verdict} should abort"
    )


def test_bundle_error_aborts_regardless_of_verdict():
    assert (
        bisect_mod.exit_code_from_cell_result(
            {"verdict": "pass", "bundle_error": "OSError"},
        )
        == bisect_mod.KSFT_ABORT
    )


def test_missing_verdict_aborts():
    assert bisect_mod.exit_code_from_cell_result({}) == bisect_mod.KSFT_ABORT
