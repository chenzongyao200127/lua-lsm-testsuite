UV ?= uv
PYTHON ?= $(UV) run python
WORKSPACE ?= $(realpath $(dir $(realpath $(firstword $(MAKEFILE_LIST))))/..)
KERNEL_TREE ?= $(WORKSPACE)/kernel/linux
TOOLS_DIR ?= $(realpath $(dir $(realpath $(firstword $(MAKEFILE_LIST))))/tools)
ROOTFS_IMG ?= $(TOOLS_DIR)/rocky9-selinux-rootfs.qcow2
KERNEL_IMG ?= $(KERNEL_TREE)/arch/x86/boot/bzImage
DEBUG_KERNEL ?= $(TOOLS_DIR)
LUA_LSM_TOOLS ?= $(WORKSPACE)/lua-lsm-tools
PARALLEL ?= 2

POLICY ?= hello

export KERNEL_TREE ROOTFS_IMG KERNEL_IMG DEBUG_KERNEL LUA_LSM_TOOLS WORKSPACE TOOLS_DIR

.PHONY: help sync smoke functional matrix matrix-perf concurrency policies \
	perf-report bisect-run image image-warm kernel-debug test lint format cov \
	selftest clean distclean

help:
	@echo "Targets:"
	@echo "  sync                         install/update the uv-managed project environment"
	@echo "  smoke POLICY=<name>          run a single smoke cell with the named policy"
	@echo "  functional                    run the self-contained policy API matrix"
	@echo "  matrix                       run the default 32-cell smoke matrix"
	@echo "  matrix-perf                  run the UnixBench-anchored matrix (opt-in)"
	@echo "  concurrency                  run register/unregister races (needs a KCSAN+lockdep kernel)"
	@echo "  policies                     run every .lua under the workspace's policy directory"
	@echo "  perf-report                  collect UnixBench scores from runs/ (report-only)"
	@echo "  bisect-run CELL=<matrix>     run a matrix as a git bisect target with KSFT exit codes"
	@echo "  image                        build the Rocky9 rootfs with the vendored helper"
	@echo "  image-warm                   pre-warm the rootfs (consume autorelabel; required before perf runs)"
	@echo "  kernel-debug PROFILE=<name>  invoke vendored enable-debug-kconfig.sh --profile {standard,full}"
	@echo "  test                         run harness unit tests with $(PYTHON)"
	@echo "  lint                         ruff check (lint)"
	@echo "  format                       ruff format (rewrite)"
	@echo "  cov                          run unit tests with coverage report"
	@echo "  selftest                     run lightweight in-tree self-tests (classifier patterns, etc.)"
	@echo "  clean                        remove generated artifacts and caches"
	@echo "  distclean                    remove generated artifacts and .venv"

sync:
	$(UV) sync --dev

smoke:
	$(PYTHON) -m harness run --headless --policy $(POLICY) --workload smoke \
		--kernel $(KERNEL_IMG) --rootfs $(ROOTFS_IMG)

matrix:
	$(PYTHON) -m harness matrix --config configs/smoke.json --parallel $(PARALLEL) \
		--kernel $(KERNEL_IMG) --rootfs $(ROOTFS_IMG)

matrix-perf:
	$(PYTHON) -m harness matrix --config configs/perf.yaml --parallel $(PARALLEL) \
		--kernel $(KERNEL_IMG) --rootfs $(ROOTFS_IMG) --share-dir $(WORKSPACE)

concurrency:
	$(PYTHON) -m harness matrix --config configs/concurrency.yaml --parallel $(PARALLEL) \
		--kernel $(KERNEL_IMG) --rootfs $(ROOTFS_IMG) --share-dir $(WORKSPACE)

policies:
	$(PYTHON) -m harness matrix --config configs/policies.yaml --parallel $(PARALLEL) \
		--kernel $(KERNEL_IMG) --rootfs $(ROOTFS_IMG) --share-dir $(WORKSPACE)

perf-report:
	$(PYTHON) -m harness perf-report --runs-root runs

bisect-run:
	@test -n "$(CELL)" || { echo "CELL=<path-to-matrix.{yaml,json}> is required"; exit 2; }
	$(PYTHON) -m harness bisect-run --config $(CELL) \
		--kernel $(KERNEL_IMG) --rootfs $(ROOTFS_IMG)

image:
	$(DEBUG_KERNEL)/create_rocky_selinux_rootfs.sh

image-warm:
	$(PYTHON) -m harness image-warm --image $(ROOTFS_IMG)

kernel-debug:
	@test -n "$(PROFILE)" || { echo "PROFILE={standard,full} is required"; exit 2; }
	@test -d "$(KERNEL_TREE)" || { echo "KERNEL_TREE=$(KERNEL_TREE) is not a directory"; exit 2; }
	$(DEBUG_KERNEL)/enable-debug-kconfig.sh --kernel $(KERNEL_TREE) --profile $(PROFILE)

test:
	$(PYTHON) -m pytest

lint:
	$(UV) run ruff check .

format:
	$(UV) run ruff format .

cov:
	$(PYTHON) -m pytest --cov=harness --cov-report=term-missing

selftest:
	$(PYTHON) -m harness.classifier_patterns --selftest
	$(PYTHON) -m harness.signature --selftest

functional:
	$(PYTHON) -m harness matrix --config configs/functional.yaml --parallel $(PARALLEL) \
		--kernel $(KERNEL_IMG) --rootfs $(ROOTFS_IMG) --share-dir $(WORKSPACE)

clean:
	rm -rf runs out __pycache__ harness/__pycache__ tests/__pycache__ \
		.pytest_cache .mypy_cache .ruff_cache .hypothesis \
		build dist .eggs *.egg-info htmlcov .coverage junit.xml

distclean: clean
	rm -rf .venv
