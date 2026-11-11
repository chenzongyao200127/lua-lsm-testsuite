# Architecture

## Repository decision

This repository owns Lua-LSM integration, stability, and performance
testing. The Linux kernel checkout remains a build and source artifact, not
the home for broad Lua-LSM test infrastructure.

The split is intentional:

- Kernel tree: kernel build, minimal ABI-level selftests only if needed for an
  upstreamable submission, and no performance or long-running stability tests.
- This repository: QEMU boot orchestration, functional assertions, stress and
  failure-injection tests, benchmark methodology, baselines, reports, and
  bisect integration.

Performance and stability tests require controlled images, kernel
configuration, host inventory, artifact retention, and statistical comparison.
Those requirements do not fit the constrained kselftest environment.

## Target shape

The current `harness/` package is infrastructure. Test intent should move into
declarative cases and fixtures so the harness stays reusable:

```text
configs/      machine matrices and named presets
fixtures/     self-contained policies, guest scripts, and golden files
docs/         architecture, operating procedures, and result contracts
harness/      execution infrastructure: VM, SSH, artifacts, classification
tests/        unit tests for the harness and test-case schemas
tools/        host and image preparation helpers
```

Future functional, performance, and stability cases should be added as
first-class fixtures and profiles rather than as more logic inside the cell
runner.

## Refactor increments

1. Keep the existing harness behavior stable while documenting the boundaries
   and result contracts.
2. ~~Split the large CLI module into small command modules without changing the
   public command surface.~~ Done: `harness/cli/` (parser + one module per
   subcommand + shared helpers); `harness/__main__.py` is a thin entrypoint
   shim. Exit-code contracts live in `harness/ksft.py` (run/matrix) and
   `harness/bisect.py` (bisect-run).
3. ~~Make fixtures self-contained in this repository and remove the dependency on
   the sibling `lua-lsm-tools` checkout for load-bearing test policies.~~ Done:
   self-contained policies live under `fixtures/policies/`; workload
   registration has a single source of truth (`workloads.SPECS`).
4. Replace historical acceptance-plan language with case names and explicit
   assertions.
5. Add a workspace inventory/doctor command before changing path defaults.
6. Add functional cases for policy API semantics, hook dispatch, duplicate and
   invalid policy rejection, and asynchronous unload.
7. Add a benchmark runner with fixed CPU affinity, warmup, repetitions,
   environment capture, variance, and baseline comparison.
8. Add stress cases for concurrent dispatch, task exit, object cleanup, and
   policy unregister.

## Non-goals

This repository is not a general-purpose VM test framework. Its abstractions
should only grow when a Lua-LSM test needs them. It also does not turn
performance numbers into pass/fail automatically: a threshold must name the
workload, baseline, environment, and noise budget.
