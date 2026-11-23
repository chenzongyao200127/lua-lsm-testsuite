"""`perf-report` subcommand: summarize UnixBench runs without failing CI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import ksft, unixbench_report


def cmd_perf_report(args: argparse.Namespace) -> int:
    cells = unixbench_report.collect(Path(args.runs_root))
    report = unixbench_report.render_markdown(cells)

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(unixbench_report.as_dict(cells), indent=2, sort_keys=True)
        )

    sys.stdout.write(report)
    if not cells:
        print(
            f"warning: no UnixBench cells found under {args.runs_root}",
            file=sys.stderr,
        )
    # Report-only by design: this command never turns scores into a verdict.
    return ksft.KSFT_PASS
