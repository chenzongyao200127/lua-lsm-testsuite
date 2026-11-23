#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Vendored UnixBench wrapper (from lua-lsm-tools/tools/lua_lsm_unixbench.sh).
# Kept in-tree so the perf cell only needs this repository plus the
# UnixBench source tree under the 9p share.
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: unixbench.sh -d <unixbench_dir> [options] [-- extra args]

Options:
  -d, --dir <dir>     Path to UnixBench directory (required)
  -o, --out <dir>     Output directory (default: /tmp/lua-lsm-unixbench-<ts>)
  -c, --cpus <n>      Pass -c <n> to UnixBench Run
  -i, --iters <n>     Pass -i <n> to UnixBench Run
  -b, --build         Build UnixBench if Run is missing
  -h, --help          Show this help
EOF
}

die() {
	echo "error: $*" >&2
	exit 1
}

UNIXBENCH_DIR=${UNIXBENCH_DIR:-}
OUT_DIR=
CPUS=
ITERS=
BUILD=0
EXTRA_ARGS=

while [ $# -gt 0 ]; do
	case "$1" in
		-d|--dir)
			UNIXBENCH_DIR=${2:-}
			shift 2
			;;
		-o|--out)
			OUT_DIR=${2:-}
			shift 2
			;;
		-c|--cpus)
			CPUS=${2:-}
			shift 2
			;;
		-i|--iters)
			ITERS=${2:-}
			shift 2
			;;
		-b|--build)
			BUILD=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		--)
			shift
			EXTRA_ARGS=$*
			break
			;;
		*)
			die "unknown option: $1"
			;;
	esac
done

[ -n "$UNIXBENCH_DIR" ] || die "UNIXBENCH_DIR is required"
[ -d "$UNIXBENCH_DIR" ] || die "missing directory: $UNIXBENCH_DIR"

if [ ! -x "$UNIXBENCH_DIR/Run" ]; then
	if [ "$BUILD" -eq 1 ]; then
		( cd "$UNIXBENCH_DIR" && make )
	else
		die "Run not found in $UNIXBENCH_DIR (use -b to build)"
	fi
fi

if [ -z "$OUT_DIR" ]; then
	ts=$(date +%Y%m%d-%H%M%S)
	OUT_DIR="/tmp/lua-lsm-unixbench-$ts"
fi
mkdir -p "$OUT_DIR"

{
	date -u
	uname -a
	[ -r /proc/cmdline ] && cat /proc/cmdline
	[ -r /sys/kernel/security/lsm ] && cat /sys/kernel/security/lsm
} > "$OUT_DIR/system.txt"

if [ -z "$CPUS" ]; then
	CPUS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi

set -- "$UNIXBENCH_DIR/Run"
[ -n "$CPUS" ] && set -- "$@" -c "$CPUS"
[ -n "$ITERS" ] && set -- "$@" -i "$ITERS"
[ -n "$EXTRA_ARGS" ] && set -- "$@" $EXTRA_ARGS

printf "Running: %s\n" "$*" | tee "$OUT_DIR/command.txt"

( cd "$UNIXBENCH_DIR" && "$@" ) | tee "$OUT_DIR/unixbench.log"

if [ -d "$UNIXBENCH_DIR/results" ]; then
	latest=$(ls -1t "$UNIXBENCH_DIR/results" 2>/dev/null | head -n 1 || true)
	if [ -n "$latest" ] && [ -e "$UNIXBENCH_DIR/results/$latest" ]; then
		cp -a "$UNIXBENCH_DIR/results/$latest" "$OUT_DIR/"
	fi
fi

echo "Results: $OUT_DIR"
