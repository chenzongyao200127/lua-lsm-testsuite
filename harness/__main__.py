"""CLI entrypoint shim for `python3 -m harness <subcommand>`.

The implementation lives in harness.cli (parser + one module per
subcommand + shared helpers in cli.common). This module stays the
`python -m harness` entrypoint and re-exports the names tests and operator
scripts historically imported from it:

    main                 -> harness.cli.main
    _resolve_policy_paths(share_dir, policy_name, workload_name)
                         -> harness.cli.common.resolve_policy_paths (same
                            argument order)

Exit codes live in harness.ksft (run/matrix, 0/1/4) and harness.bisect
(bisect-run, 0/1/125/128). See harness.cli's package docstring for the
subcommand/exit-code contract.
"""

from __future__ import annotations

import subprocess  # noqa: F401  (tests patch cli.subprocess.run in place)
import sys

from .cli import main
from .cli.common import resolve_policy_paths as _resolve_policy_paths
from .hostenv import UnsupportedHostError

__all__ = [
    "_resolve_policy_paths",
    "main",
]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except UnsupportedHostError as e:
        print(e.message, file=sys.stderr)
        sys.exit(2)
