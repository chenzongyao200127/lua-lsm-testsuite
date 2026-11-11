"""Shared value types for cells and workloads.

Split out of harness.cell_runner so harness.workloads can own the workload
registry (specs, fixtures, policy resolution) without importing the cell
runner -- the cell runner imports the registry instead, and the registry
never imports back. cell_runner re-exports these names, so historical
`from harness.cell_runner import CellContext` imports keep working.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import ssh


@dataclass
class WorkloadResult:
    name: str
    returncode: int = 0
    notes: str = ""


@dataclass
class CellContext:
    cell_id: str
    artifact_dir: Path
    target: ssh.SshTarget
    profile: Mapping[str, Any]
    commands: list[str] = field(default_factory=list)

    def record_command(self, cmd: str) -> None:
        """Append a guest-side command to the cell's replay log.

        Workloads call this for every shell command they push through SSH so
        the bundle's commands.sh can replay the cell without parsing the
        cell's per-workload log files.
        """
        self.commands.append(cmd)

    def with_profile(self, **overrides: Any) -> CellContext:
        """Return a copy sharing commands/artifact_dir with a patched profile.

        Used by composite workloads (bench-short's paired load/unload) that
        run one workload function twice with slightly different profiles while
        accumulating commands in the same replay log.
        """
        profile = dict(self.profile)
        profile.update(overrides)
        return CellContext(
            cell_id=self.cell_id,
            artifact_dir=self.artifact_dir,
            target=self.target,
            profile=profile,
            commands=self.commands,
        )


WorkloadFn = Callable[[ssh.SshTarget, CellContext], WorkloadResult]
