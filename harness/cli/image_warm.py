"""`image-warm` subcommand: write the rootfs warm-marker once."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import preflight
from ..ksft import KSFT_FAIL, KSFT_PASS


def cmd_image_warm(args: argparse.Namespace) -> int:
    image = Path(args.image)
    if not image.exists():
        print(f"error: image not found: {image}", file=sys.stderr)
        return KSFT_FAIL
    marker = Path(args.marker) if args.marker else preflight.default_warm_marker(image)
    try:
        marker.write_text(f"warm: {image}\n")
    except OSError as e:
        print(f"error: cannot write {marker}: {e}", file=sys.stderr)
        return KSFT_FAIL
    print(f"warm-marker: {marker}")
    return KSFT_PASS
