"""Active-QEMU registry for SIGINT-driven matrix-wide reap.

The matrix executor needs to kill any QEMU children that are still running
when a SIGINT lands, otherwise a wedged workload can stall the whole run
indefinitely. The registry is a thread-safe map from cell_id to QemuHandle
shared between the matrix executor (which raises SIGINT and drives the
reap) and the per-cell runner (which spawns QEMU and registers/unregisters
the handle around the workload).

The default reap grace is `SHUTDOWN_GRACE_S` per handle: SIGTERM, then
SIGKILL after the grace if the launcher hasn't exited. Reap exceptions
are swallowed -- a registry-driven cleanup must be best-effort because a
single stuck handle should not block the rest of the matrix from being
written out as `aborted`.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import qemu  # only for type hints; avoid runtime import cycle.


SHUTDOWN_GRACE_S: float = 10.0


class RunRegistry:
    """Thread-safe map cell_id -> active QemuHandle.

    The registry is process-local (no file backing): a fresh harness run
    starts empty. Re-entry across cells uses the same registry so a SIGINT
    landing during cell N reaps cells {0..N-1, N} that haven't returned yet.
    """

    def __init__(self) -> None:
        self._handles: dict[str, "qemu.QemuHandle"] = {}
        self._lock = threading.Lock()

    def register(self, cell_id: str, handle: "qemu.QemuHandle") -> None:
        with self._lock:
            self._handles[cell_id] = handle

    def unregister(self, cell_id: str) -> None:
        with self._lock:
            self._handles.pop(cell_id, None)

    def active_cells(self) -> list[str]:
        with self._lock:
            return list(self._handles.keys())

    def stop_all(self, timeout_s: float = SHUTDOWN_GRACE_S) -> list[str]:
        """SIGTERM-then-SIGKILL every active QEMU child.

        Returns the list of cell_ids whose handles were reaped (best-effort).
        Swallows per-handle exceptions: a single stuck handle must not
        prevent the matrix from finalising.
        """
        from . import qemu  # local import to avoid cycle.
        with self._lock:
            handles = list(self._handles.items())
            self._handles.clear()
        reaped: list[str] = []
        for cell_id, handle in handles:
            try:
                qemu.stop(handle, timeout_s=timeout_s)
                reaped.append(cell_id)
            except Exception:
                # A reap that fails is still a reap attempt; record it so the
                # matrix executor can correlate with the cell list, but do
                # not propagate the exception.
                reaped.append(cell_id)
        return reaped
