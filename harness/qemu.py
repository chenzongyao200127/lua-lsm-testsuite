"""Spawn the debug-kernel QEMU via the vendored run_qemu_anolis.sh launcher.

This module shells out to the vendored launcher script rather than
constructing a QEMU command line directly: that script is the project's
authoritative source for the kernel-debug invocation (gdbstub, panic knobs,
serial console, virtio-9p host_share, SSH portfwd) and we want every cell to
match what a developer would run interactively.

The launcher supports optional pidfile/monitor-socket env knobs, but the
current stop path still records the launcher PID and reaps the process tree
via process group on stop.
"""

from __future__ import annotations

import contextlib
import os
import shlex
import signal
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class QemuLaunchError(RuntimeError):
    pass


@dataclass
class QemuHandle:
    proc: subprocess.Popen
    serial_log_path: Path
    pgid: int
    started_at: float


def spawn(
    launcher: Path,
    env: Mapping[str, str],
    serial_log_path: Path,
    cwd: Path | None = None,
    interactive: bool = False,
) -> QemuHandle:
    """Launch QEMU via the vendored launcher.

    In headless mode (the default), stdout+stderr from the launcher (which
    includes the QEMU serial console when the launcher forwards `-serial
    stdio`) is piped to `serial_log_path` so the cell runner can classify
    splats afterwards.

    In interactive mode (`interactive=True`), the launcher inherits the
    parent's stdio so the user gets the real QEMU console on their terminal;
    `serial_log_path` is created (so the artifact directory still has the
    file slot) but no bytes are routed into it from this process.

    The child runs in its own process group so a stop() can kill the whole
    tree even if the launcher exec'd qemu rather than exec-replacing into it.
    """
    if not Path(launcher).exists():
        raise QemuLaunchError(f"launcher not found: {launcher}")
    serial_log_path.parent.mkdir(parents=True, exist_ok=True)
    full_env = dict(os.environ)
    full_env.update({k: str(v) for k, v in env.items()})
    fp = None
    try:
        if interactive:
            # Touch the serial log so the artifact slot exists even though we
            # don't redirect into it; an interactive run can still scrape
            # dmesg via SSH at teardown.
            serial_log_path.touch(exist_ok=True)
            stdout_arg: int | None = None  # inherit
            stderr_arg: int | None = None  # inherit
        else:
            fp = serial_log_path.open("wb", buffering=0)
            stdout_arg = fp.fileno()
            stderr_arg = subprocess.STDOUT
        try:
            proc = subprocess.Popen(
                ["/bin/bash", str(launcher)],
                stdout=stdout_arg,
                stderr=stderr_arg,
                env=full_env,
                cwd=str(cwd) if cwd else None,
                start_new_session=True,
            )
        except OSError as e:
            # Exec failures (missing /bin/bash, permission denied, ENOMEM)
            # must not escape as raw OSError: the cell runner only normalises
            # QemuLaunchError into a harness-error verdict, and an unwrapped
            # OSError would bypass result.json finalisation entirely.
            raise QemuLaunchError(f"failed to spawn launcher {launcher}: {e}") from e
    finally:
        # Once Popen has duped the fd into the child, the parent-side handle
        # is no longer needed; closing it lets the parent exit cleanly even
        # if the child outlives the harness process group.
        if fp is not None:
            fp.close()
    return QemuHandle(
        proc=proc,
        serial_log_path=serial_log_path,
        pgid=os.getpgid(proc.pid),
        started_at=time.time(),
    )


def stop(handle: QemuHandle, timeout_s: float = 10.0) -> int:
    """Terminate the QEMU process group; SIGKILL after timeout.

    Returns the launcher exit code (or -SIGNAL on signal-induced termination).
    Safe to call when the launcher has already exited.
    """
    if handle.proc.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(handle.pgid, signal.SIGTERM)
        try:
            handle.proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(handle.pgid, signal.SIGKILL)
            handle.proc.wait(timeout=5.0)
    return handle.proc.returncode if handle.proc.returncode is not None else -1


def render_launch_command(launcher: Path, env: Mapping[str, str]) -> str:
    """Reproduce the env+launcher invocation as a copy-pasteable shell line.

    Used for qemu-cmdline.txt in bundles so a kernel developer can re-run the
    same cell by hand without parsing JSON.
    """
    parts = [f"{k}={shlex.quote(str(v))}" for k, v in sorted(env.items())]
    parts.append(shlex.quote(str(launcher)))
    return " ".join(parts)
