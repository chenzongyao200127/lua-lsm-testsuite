# Legacy launcher patches (DEC-4)

These patches were originally carried for an external
`run_qemu_anolis.sh` launcher so the harness could manage QEMU lifecycle
deterministically.

| Patch | Env var | What it does |
| ----- | ------- | ------------ |
| `0001-...` | `QEMU_PIDFILE` | Pass `-pidfile $QEMU_PIDFILE` to QEMU; harness uses it for clean signalling at boot-timeout. |
| `0002-...` | `QEMU_MONITOR_SOCK` | Pass `-monitor unix:$QEMU_MONITOR_SOCK,server,nowait` so the harness can issue QMP `system_powerdown` / `quit` for graceful shutdown. |

The current repo vendors the launcher in `tools/run_qemu_anolis.sh`, and
that local copy already carries the equivalent support. These patches are
kept only as historical reference for any external launcher that still needs
the same hooks.
