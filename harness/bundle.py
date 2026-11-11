"""Reproducer-bundle writer with first-occurrence dedup.

When a cell's verdict is `kernel-bug`, the harness builds a bundle keyed by
the splat signature (harness.signature.build_signature) so that re-runs of
the same bug under different cell axes don't all produce full duplicate
bundles -- the second occurrence's bundle is just `metadata.json` +
`dup_of.txt` pointing at the first.

The bundle payload is the bisect-ready set a kernel developer needs to repro
a splat:

    kernel.sha       git rev-parse HEAD of the kernel tree built for this cell
    .config          the kernel build's .config (verbatim)
    config.diff      diff of .config against the matrix's baseline kconfig
    cmdline          the EXTRA_CMDLINE composed for this cell
    commands.sh      ordered guest commands replayed by the cell, as a script
    policies/*.lua   the lua policies the cell registered (one file per policy)
    rootfs.sha256    sha256 of the rootfs image used to boot this cell
    serial.log       raw QEMU serial console log (verbatim)
    dmesg.txt        guest dmesg slice captured at teardown
    decoded.txt      stdout of scripts/decode_stacktrace.sh on the splat slice
                     (or decoder stderr if the decoder failed)
    signature        the sha1 signature plus its kind (primary/fallback)

`signature_kind` distinguishes splats parsed from the splat header from those
inferred from surrounding frames when the header was unparseable.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import schemas
from .timeutil import now_iso


@dataclass
class BundleSources:
    """Inputs the bundle writer needs to assemble the payload.

    Most fields are optional: the writer copes with missing pieces by writing
    a marker file (e.g. an empty config.diff, a stub commands.sh) so the
    bundle directory still has a complete file list. A bisect-bundle that
    can be partially populated is more useful than no bundle at all.
    """

    cell_id: str
    artifact_dir: Path
    cmdline: str
    kernel_tree: Path | None = None
    kernel_config_path: Path | None = None
    kernel_config_baseline: Path | None = None
    rootfs_image: Path | None = None
    policies: Sequence[Path] = field(default_factory=tuple)
    commands: Sequence[str] = field(default_factory=tuple)
    decode_script: Path | None = None
    splat_slice: Sequence[str] = field(default_factory=tuple)


@dataclass
class BundleStore:
    """Process-local map of signature_sha1 -> first-occurrence bundle dir.

    The store is intentionally in-memory: bundles live inside each cell's own
    artifact_dir (`<artifact_dir>/bundle/`), so the store only needs to know
    which signature has been seen and which cell directory carries the
    payload. matrix.json + per-bundle metadata.json are the persistent record.
    A fresh harness run starts with an empty store so a re-run of the same
    matrix produces fresh first-occurrence bundles.
    """

    _seen: dict[str, Path] = None  # type: ignore[assignment]
    _lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._seen = {}
        self._lock = threading.Lock()


def _now_iso() -> str:
    # Kept as a thin alias: call sites predate harness.timeutil.
    return now_iso()


def _git_head_sha(tree: Path) -> str | None:
    if not Path(tree).exists():
        return None
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(tree),
            capture_output=True,
            timeout=10,
        )
        if r.returncode == 0:
            return r.stdout.decode("utf-8", errors="replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


def _sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fp:
            for chunk in iter(lambda: fp.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _diff_configs(current: Path | None, baseline: Path | None) -> str:
    if current is None or baseline is None:
        return ""
    if not current.exists() or not baseline.exists():
        return ""
    try:
        r = subprocess.run(
            ["diff", "-u", str(baseline), str(current)],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"# diff failed: {type(e).__name__}: {e}\n"
    return r.stdout.decode("utf-8", errors="replace")


def _decode_trace(
    decode_script: Path | None, kernel_tree: Path | None, splat_slice: Sequence[str]
) -> str:
    """Run scripts/decode_stacktrace.sh on the splat slice; return its output.

    On any failure (script missing, exec error, non-zero exit) the returned
    text starts with a `# decode failed:` marker plus the original stderr,
    so the bundle still has a decoded.txt and the caller can diagnose.
    """
    if not splat_slice:
        return "# no splat slice provided\n"
    text = "\n".join(splat_slice).rstrip() + "\n"
    if decode_script is None or not Path(decode_script).exists():
        return f"# decode_stacktrace.sh not available\n# raw splat slice follows\n{text}"
    if kernel_tree is None or not Path(kernel_tree).exists():
        return f"# kernel tree path missing\n# raw splat slice follows\n{text}"
    try:
        r = subprocess.run(
            [str(decode_script), "vmlinux"],
            cwd=str(kernel_tree),
            input=text.encode("utf-8"),
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"# decode failed: {type(e).__name__}: {e}\n# raw splat slice follows\n{text}"
    if r.returncode != 0:
        stderr = r.stderr.decode("utf-8", errors="replace")
        stdout = r.stdout.decode("utf-8", errors="replace")
        return (
            f"# decode failed: rc={r.returncode}\n"
            f"# stderr:\n{stderr}\n"
            f"# stdout:\n{stdout}\n"
            f"# raw splat slice follows\n{text}"
        )
    return r.stdout.decode("utf-8", errors="replace") or text


def _write_payload(
    bundle_dir: Path, sources: BundleSources, signature_sha1: str, signature_kind: str
) -> None:
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # kernel.sha: git HEAD of the kernel tree, or "unknown" marker.
    sha = _git_head_sha(sources.kernel_tree) if sources.kernel_tree else None
    (bundle_dir / "kernel.sha").write_text((sha or "unknown") + "\n")

    # .config: copy the kernel build config; if absent, write a marker.
    if sources.kernel_config_path and Path(sources.kernel_config_path).exists():
        shutil.copy2(sources.kernel_config_path, bundle_dir / ".config")
    else:
        (bundle_dir / ".config").write_text("# kernel .config not available\n")

    # config.diff: diff against baseline if both present, else empty marker.
    diff_text = _diff_configs(sources.kernel_config_path, sources.kernel_config_baseline)
    (bundle_dir / "config.diff").write_text(diff_text or "# no diff available\n")

    # cmdline: the EXTRA_CMDLINE composed for this cell.
    (bundle_dir / "cmdline").write_text(sources.cmdline.rstrip("\n") + "\n")

    # commands.sh: ordered guest replay script. Generated even when empty so
    # the file is always present.
    cmds = list(sources.commands or ())
    script_lines = ["#!/bin/sh", "set -eu", "# replay of guest commands captured during this cell."]
    if not cmds:
        script_lines.append("# (no commands captured for this cell)")
    else:
        script_lines.extend(cmds)
    (bundle_dir / "commands.sh").write_text("\n".join(script_lines) + "\n")
    (bundle_dir / "commands.sh").chmod(0o755)

    # policies/: copy each registered .lua policy. The directory always
    # exists, so a bundle with zero policies still has the slot.
    pol_dir = bundle_dir / "policies"
    pol_dir.mkdir(parents=True, exist_ok=True)
    for pol in sources.policies or ():
        pol_path = Path(pol)
        if pol_path.exists():
            shutil.copy2(pol_path, pol_dir / pol_path.name)

    # rootfs.sha256: hash of the actual rootfs image. None when image was
    # unreachable (e.g. mocked tests).
    if sources.rootfs_image and Path(sources.rootfs_image).exists():
        digest = _sha256_file(Path(sources.rootfs_image))
        (bundle_dir / "rootfs.sha256").write_text((digest or "unknown") + "\n")
    else:
        (bundle_dir / "rootfs.sha256").write_text("unknown\n")

    # serial.log: copy the cell's raw serial log if it exists.
    src_serial = sources.artifact_dir / "serial.log"
    if src_serial.exists():
        shutil.copy2(src_serial, bundle_dir / "serial.log")
    else:
        (bundle_dir / "serial.log").write_text("# serial.log not captured\n")

    # dmesg.txt: when the caller provided a slice (the small window centered
    # on the first classifier hit), write that instead of the full dmesg log.
    # The slice is the bisect-friendly view -- a kernel developer can
    # re-orient on a splat without paging through tens of thousands of lines.
    # If no slice was provided we fall back to copying dmesg.log so unit
    # tests and ad-hoc bundles still see the full file.
    if sources.splat_slice:
        slice_text = "\n".join(sources.splat_slice).rstrip() + "\n"
        (bundle_dir / "dmesg.txt").write_text(slice_text)
    else:
        src_dmesg = sources.artifact_dir / "dmesg.log"
        if src_dmesg.exists():
            shutil.copy2(src_dmesg, bundle_dir / "dmesg.txt")
        else:
            (bundle_dir / "dmesg.txt").write_text("# dmesg.log not captured\n")

    # decoded.txt: scripts/decode_stacktrace.sh output (or decoder stderr).
    decoded = _decode_trace(sources.decode_script, sources.kernel_tree, sources.splat_slice)
    (bundle_dir / "decoded.txt").write_text(decoded)

    # signature: sha1 + kind, on two lines so a developer can `head -2`.
    (bundle_dir / "signature").write_text(f"{signature_sha1}\n{signature_kind}\n")


def write_bundle(
    store: BundleStore,
    sources: BundleSources,
    signature_sha1: str,
    signature_kind: str,
) -> Path:
    """Write a bundle for `sources.cell_id`. Returns the bundle directory.

    The bundle lives inside the cell's own artifact directory at
    `<sources.artifact_dir>/bundle/`. On first occurrence of `signature_sha1`,
    writes the full reproducer payload (`kernel.sha`, `.config`, `config.diff`,
    `cmdline`, `commands.sh`, `policies/*.lua`, `rootfs.sha256`, `serial.log`,
    `dmesg.txt`, `decoded.txt`, `signature`) plus `metadata.json`. On later
    occurrences of the same signature, writes only `metadata.json` and
    `dup_of.txt` pointing at the first occurrence's bundle directory
    (relative path computed from this bundle dir to the first bundle dir).
    """
    bundle_dir = Path(sources.artifact_dir) / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    metadata = schemas.empty_bundle_metadata(sources.cell_id, signature_sha1, signature_kind)
    metadata["first_seen_at"] = _now_iso()

    with store._lock:
        first_dir = store._seen.get(signature_sha1)
        if first_dir is None:
            store._seen[signature_sha1] = bundle_dir
            is_dup = False
        else:
            is_dup = True
            # Relative path from this bundle dir to the first-occurrence bundle dir,
            # so a developer can `cat dup_of.txt && cd "$(cat dup_of.txt)"` from
            # inside any duplicate bundle.
            metadata["dup_of"] = os.path.relpath(first_dir, start=bundle_dir)

    if is_dup:
        (bundle_dir / "dup_of.txt").write_text(metadata["dup_of"] + "\n")
    else:
        _write_payload(bundle_dir, sources, signature_sha1, signature_kind)

    (bundle_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True))
    return bundle_dir
