"""Time helpers shared across the harness."""

from __future__ import annotations

import datetime as _dt


def now_iso() -> str:
    """Current UTC time, second precision, ISO-8601.

    The timespec matches every result.json / matrix.json timestamp field, so
    artifacts written at different layers stay string-comparable.
    """
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
