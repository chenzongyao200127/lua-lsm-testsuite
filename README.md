# lua-lsm-testsuite

Out-of-tree QEMU matrix test harness for the Linux Lua LSM (`security/lua/`).

This harness lives outside the kernel tree and integrates with sibling
checkouts under a shared workspace:

```
<workspace>/
  kernel/linux/         # the kernel source tree under test
  lua-lsm-tools/        # example policies and per-cell helpers
  lua-lsm-testsuite/    # this harness
```

The harness drives one boot of a fresh debug-kernel QEMU VM as a single test
cell, captures dmesg / serial / journalctl, classifies splats with anchored
patterns, snapshots `/sys/kernel/security/lua/{stats,lsm_funcs}`, and writes
bisect-ready bundles on first-occurrence kernel splats.

## Quick start

```sh
# Create the uv-managed project environment with runtime + dev tools.
uv sync --dev

# Smoke a single cell against an already-built kernel
make smoke POLICY=hello

# Run the default 32-cell smoke matrix
make matrix

# Run as a git bisect target (the matrix verdict drives the bisect step)
git bisect run uv run python -m harness bisect-run \
    --config configs/smoke.yaml \
    --kernel arch/x86/boot/bzImage \
    --rootfs path/to/rootfs.img

# Boot a guest and leave it up for SSH-driven debug
uv run python -m harness run --detach-vm \
    --kernel arch/x86/boot/bzImage \
    --rootfs path/to/rootfs.img
```

The CLI accepts `--kernel`, `--rootfs`, `--config`, and `--image` (image-warm)
as the canonical flags; older flags such as `--kernel-image` have been
removed and the standalone `scripts/bisect-run.sh` shell wrapper is no
longer needed.

### Live KVM acceptance dry run

The harness REFUSES to plan on macOS, so the end-to-end boot/SSH/workload/
teardown path is exercised from a Linux KVM host via the reproducible
handoff script. The recommended operator workflow is two steps:

```sh
# Step 1: confirm the host is ready (no harness spawn, fast feedback)
WORKSPACE=/work \
KERNEL=/work/kernel/linux/arch/x86/boot/bzImage \
ROOTFS=/work/images/rocky9.img \
    scripts/linux-kvm-dry-run.sh --prereqs-only

# Step 2: run the full acceptance sequence
WORKSPACE=/work \
KERNEL=/work/kernel/linux/arch/x86/boot/bzImage \
ROOTFS=/work/images/rocky9.img \
    scripts/linux-kvm-dry-run.sh
```

`--prereqs-only` validates the host gate (Linux), required env vars
(`KERNEL`, `ROOTFS`), sibling-checkout layout (`lua-lsm-tools/`,
`kernel/linux/`, and `lua-lsm-testsuite/` under `WORKSPACE`), file
readability for `KERNEL` and `ROOTFS`, that the QEMU `LAUNCHER` is a
readable+executable file, and `/dev/kvm` presence + readability. Fix any
reported issue before triggering the full run.

The optional `LAUNCHER` env var defaults to
`${WORKSPACE}/lua-lsm-testsuite/tools/run_qemu_anolis.sh` and is passed as
`--launcher` to every harness invocation. The script also
passes `--share-dir "${WORKSPACE}"` to every harness invocation so
the guest sees `/mnt/host/lua-lsm-tools/` for workload helpers.

The full run executes (1) a single-cell smoke, (2) a bounded 4-cell smoke
matrix on distinct ports, (3) a warmed-image UnixBench perf cell with
`denyfile.lua` (the AC-5.1 hook-delta acceptance proof), (4) an LKDTM
positive-control cell, and (5) the AC-9 `skip:no-kvm` code path via a
`LUA_LSM_TESTSUITE_KVM_PATH=/nonexistent` env override applied to that
one step (the cell stays `kvm_required=True`; the override makes
hostenv detection report no `/dev/kvm`, which is the real input the
runner's skip branch needs). The earlier `--no-kvm` CLI flag is for a
different case — it means "this cell does not require KVM" — and so
cannot exercise the skip branch.

The script prints the artifact directory after each step and tees its
full stdout+stderr to `${RUNS_ROOT}/dry-run-<UTC>.log` so the operator's
paste-back artifact trail is unambiguous. The header documents the exact
artifact paths each step produces (the "Artifact-path map per step"
block), so a reviewer can verify the paste-back without re-reading
harness internals.

## Host requirements

- Linux host with `/dev/kvm` for perf cells. macOS is **not supported**:
  the harness exits at planning time on `uname -s == Darwin`.
- Python 3.9+.
- `uv` for environment and command management.
- `PyYAML` for YAML-backed matrix or cell profiles.
- A built `bzImage` and a compatible rootfs image. The repo vendors
  `tools/create_rocky_selinux_rootfs.sh` for building the default Rocky9
  image under `tools/`.

## Layout

```
lua-lsm-testsuite/
  Makefile              targets: matrix, smoke, bisect-run, image, kernel-debug, test
  harness/              Python sources (cell_runner, classifier, bundler, ...)
  configs/              YAML cell and matrix profiles
  tools/                vendored VM launcher and host-side helper scripts
  patches/              legacy external-launcher patches (kept for reference)
  runs/                 per-cell artifact directories (gitignored)
  out/                  ad hoc local reports/results (gitignored)
  scripts/              reproducible operator helpers (linux-kvm-dry-run.sh)
  tests/                unit tests for harness components
```

## Development

```sh
# Install or refresh the local development environment.
make sync

# Run the test suite via pytest (pytest collects the existing unittest tests).
make test

# Remove local harness outputs and Python cache files.
make clean
```

## Plan reference

This implementation is driven by the converged plan at
`kernel/linux/.humanize/plans/lua-lsm-out-of-tree-qemu-matrix-harness-20260525-110738.md`.
