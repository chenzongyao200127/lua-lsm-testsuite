"""CLI entrypoint shim for `python3 -m harness <subcommand>`.

The implementation lives in harness.cli (parser + one module per
subcommand + shared helpers in cli.common). This module stays the
`python -m harness` entrypoint and re-exports the names tests and operator
scripts historically imported from it:

    main                 -> harness.cli.main
    KSFT_PASS/FAIL/SKIP  -> harness.ksft (run/matrix contract, 0/1/4)
    _resolve_policy_paths(share_dir, policy_name, workload_name)
                         -> harness.cli.common.resolve_policy_paths (same
                            argument order)

See harness.cli's package docstring for the subcommand/exit-code contract.
"""

from __future__ import annotations

import subprocess  # noqa: F401  (tests patch cli.subprocess.run in place)
import sys

from .cli import main
from .cli.common import resolve_policy_paths as _resolve_policy_paths
from .hostenv import UnsupportedHostError
from .ksft import KSFT_FAIL, KSFT_PASS, KSFT_SKIP

__all__ = [
    "KSFT_FAIL",
    "KSFT_PASS",
    "KSFT_SKIP",
    "_resolve_policy_paths",
    "main",
]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except UnsupportedHostError as e:
        print(e.message, file=sys.stderr)
        sys.exit(2)
