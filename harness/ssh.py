"""SSH transport helpers for driving the guest from the host.

We shell out to the system's ssh/scp binaries instead of pulling in paramiko
or asyncssh — the harness must run from a stock Linux build host without any
Python network stack beyond what's already in the standard library.

Conventions:
- The guest forwards localhost:HOST_SSH_PORT -> guest:22 via QEMU user net.
- The harness assumes the rootfs ships an SSH key that's been provisioned by
  the local rootfs builder; the key path is passed in explicitly.
- StrictHostKeyChecking is disabled and the known_hosts file is forced to
  /dev/null because every cell brings up a fresh VM with a fresh host key.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SshTarget:
    host: str  # typically "127.0.0.1"
    port: int  # HOST_SSH_PORT
    user: str  # typically "root"
    key_path: Path  # private key for cell


def _base_ssh_args(target: SshTarget) -> list[str]:
    return [
        "ssh",
        "-i",
        str(target.key_path),
        "-p",
        str(target.port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        f"{target.user}@{target.host}",
    ]


def wait_for_ssh(target: SshTarget, timeout_s: float = 120.0, poll_s: float = 1.0) -> bool:
    """Poll until `ssh ... true` succeeds or the deadline passes.

    Returns True on success, False on timeout. We deliberately don't probe a
    raw TCP socket: an open socket means sshd is listening, but it doesn't
    mean the guest has finished early-userspace and is willing to authenticate.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(
                [*_base_ssh_args(target), "-o", "ConnectTimeout=2", "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if r.returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(poll_s)
    return False


@dataclass
class SshResult:
    returncode: int
    stdout: str
    stderr: str


def run(target: SshTarget, cmd: str, timeout_s: float = 120.0) -> SshResult:
    """Run a shell command in the guest and capture stdout/stderr.

    `cmd` is passed through `bash -lc <cmd>` so login-profile env (PATH for
    /sbin, etc.) is loaded; callers should pre-quote any arguments with
    shlex.quote.
    """
    # ssh concatenates trailing argv with spaces before handing them to the
    # remote shell, so `["bash", "-lc", cmd]` becomes `bash -lc <cmd...>` and
    # bash interprets the words after `-c <first-word>` as positional params
    # ($0, $1, ...). Quote the whole `bash -lc <cmd>` as a single ssh arg.
    remote = f"bash -lc {shlex.quote(cmd)}"
    proc = subprocess.run(
        [*_base_ssh_args(target), remote],
        capture_output=True,
        timeout=timeout_s,
    )
    return SshResult(
        returncode=proc.returncode,
        stdout=proc.stdout.decode("utf-8", errors="replace"),
        stderr=proc.stderr.decode("utf-8", errors="replace"),
    )


def fetch_text(target: SshTarget, remote_path: str, timeout_s: float = 30.0) -> str | None:
    """Cat a remote file back over the existing ssh transport.

    Returns None if the cat exits non-zero (file missing, permission denied).
    Used for stats/lsm_funcs/journalctl snapshots; fetch is small enough that
    a separate scp invocation per file would be wasteful.
    """
    r = run(target, f"cat {shlex.quote(remote_path)}", timeout_s=timeout_s)
    if r.returncode != 0:
        return None
    return r.stdout
