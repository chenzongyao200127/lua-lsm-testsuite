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

# Run the self-contained policy API and dispatch assertions
make functional KERNEL_IMG=/path/to/bzImage ROOTFS_IMG=/path/to/rootfs.img

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

### CI suites

Beyond the smoke/functional matrices, three opt-in suites are shipped here
and wired into the kernel repository's GitHub Actions workflow:

```sh
# Register/unregister races against 4 workers; run it on a KCSAN + lockdep
# kernel (kind: bughunt turns any splat into a cell failure).
make concurrency KERNEL_IMG=/path/to/kcsan-bzImage

# Run every policy auto-discovered under
# $WORKSPACE/kernel/linux/.github/ci/policies/*.lua. A policy may ship a
# companion <name>.sh whose exit code becomes the case verdict.
make policies

# UnixBench, report-only: scores are collected, never turned into a verdict.
make matrix-perf
make perf-report     # markdown table + per-policy medians from runs/
```

- **Concurrency** (`workload: concurrency`): the guest starts N file/task
  churn workers, then repeatedly unregisters, re-registers, races a
  duplicate register, and waits for module drain. It asserts the duplicate
  is rejected, every unregister drains, and the module list ends clean.
  Kernel splats are what fail the cell, so use the debug fragment in
  `kernel.config.concurrency` (KCSAN + PROVE_LOCKING + PREEMPT).
- **Policies** (`workload: policy-suite` + `discover`): matrix discovery
  expands one cell per discovered `.lua`, so adding a policy to the kernel
  repo's `.github/ci/policies/` directory is enough to get it tested. The
  file name must match the policy's `name` field (unregister is by name).
- **UnixBench** (`workload: unixbench`): `harness perf-report` parses the
  `System Benchmarks Index Score` table and reports per-policy medians.
  The subcommand always exits 0 by design.

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
  Makefile              targets: matrix, smoke, concurrency, policies, bisect-run, image, kernel-debug, test
  harness/              Python sources (cell_runner, classifier, bundler, ...)
  configs/              YAML cell and matrix profiles
  tools/                vendored VM launcher and host-side helper scripts
  runs/                 per-cell artifact directories (gitignored)
  out/                  ad hoc local reports/results (gitignored)
  scripts/              reproducible operator helpers (linux-kvm-dry-run.sh)
  tests/                unit tests for harness components
```

See `docs/ARCHITECTURE.md` for the split between this repository and the
kernel tree, plus the incremental cleanup plan. Performance gate philosophy is
recorded in `docs/EBPF_GUARDRAILS.md`.

## Development

The project is uv-managed; the dev environment brings pytest, pytest-cov,
and ruff. The Makefile is the front door:

```sh
# Install or refresh the local development environment.
make sync

# Run the full test suite.
make test

# Fast gate: everything except the script-pinning tests (marked slow).
uv run python -m pytest -q -m "not slow"

# Lint and format.
make lint
uv run ruff format .

# Test coverage report (branch coverage over harness/).
make cov

# Built-in classifier/signature self-tests.
make selftest

# Remove local harness outputs and Python cache files.
make clean
```

Sanity-check a matrix config without touching QEMU — planning is pure:

```sh
uv run python -c "from pathlib import Path; from harness import matrix; \
print(len(matrix.plan_from_file(Path('configs/smoke.yaml')).cells))"
# -> 32
```

## Plan reference

Architecture and cleanup direction live in `docs/ARCHITECTURE.md`.
