"""KSFT exit codes for the `run` and `matrix` subcommands.

These are the kselftest-style codes the CLI contract documents:
    0   pass
    1   any non-pass non-skip verdict
    4   skip

`bisect-run` uses a DIFFERENT, git-bisect-shaped contract (0/1/125/128)
owned by harness.bisect; the two tables are intentionally separate.
"""

from __future__ import annotations

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_SKIP = 4

# Historical names, re-exported for callers written against the old
# harness.__main__ constants.
KSFT_PASS = EXIT_PASS
KSFT_FAIL = EXIT_FAIL
KSFT_SKIP = EXIT_SKIP
