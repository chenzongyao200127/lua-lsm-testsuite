"""CLI package for `python3 -m harness <subcommand>`.

Subcommands:
    run          single-cell run, ad-hoc invocation          (cli.run)
    matrix       expand a matrix YAML/JSON and run every cell (cli.matrix_cmd)
    bisect-run   matrix/cell exit codes shaped for git-bisect (cli.bisect_run)
    image-warm   write the rootfs warm-marker file once       (cli.image_warm)
    perf-report  collect UnixBench scores (report-only)        (cli.perf_report)

The CLI does not implement boot/shell logic itself: it constructs a
CellInputs / MatrixPlan and hands it to harness.cell_runner.run_cell or
harness.matrix.run_matrix. This keeps the surface area small and the
orchestration testable -- the integration tests mock qemu.spawn /
ssh.run / ssh.wait_for_ssh and assert on the dispatcher.

Refusal at planning time:
    - Darwin host -> hostenv.assert_supported raises before any runs/ dir.
    - --detach-vm in matrix/bisect-run -> argparse rejects it (interactive
      mode is per-cell only).
    - SHARE_DIR missing the entries required by the selected workloads.

Exit codes:
    run         0 on pass, 1 on any non-pass non-skip; KSFT 4 on skip.
    matrix      0 on pass, 1 on any failed cell; KSFT 4 on all-skip.
    bisect-run  bisect.exit_code_from_matrix (0/1/125/128).
    image-warm  0 on success, 1 on missing image / write failure.
    perf-report 0 always (scores are collected, never gated).
"""

from __future__ import annotations

from .parser import build_parser

__all__ = ["build_parser", "main"]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
