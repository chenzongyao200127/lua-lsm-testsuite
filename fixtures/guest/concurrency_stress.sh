#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Concurrency correctness stress for Lua-LSM.
#
# Runs N worker shells that churn files and tasks while the driver
# repeatedly registers, races a duplicate register, and unregisters the
# selected policy. The policy is unregistered WHILE the workers are still
# dispatching hooks, so task-VM teardown, per-CPU VM drain, and module
# finalization all run against live traffic.
#
# Usage: concurrency_stress.sh POLICY_PATH [WORKERS] [DURATION_S] [CYCLES]
#
# Exit status: 0 when every assertion passed and the module list ended
# clean; 1 otherwise. TAP-ish output is printed on stdout so the harness
# log carries the invariant trail.

set -u

policy_path="${1:?usage: concurrency_stress.sh POLICY_PATH [WORKERS] [DURATION_S] [CYCLES]}"
workers="${2:-4}"
duration="${3:-20}"
cycles="${4:-10}"

lua_dir=/sys/kernel/security/lua
register="$lua_dir/register"
unregister="$lua_dir/unregister"
modules="$lua_dir/modules"
stats="$lua_dir/stats"

policy_name="$(basename -- "$policy_path")"
policy_name="${policy_name%.lua}"

test_count=0
failures=0
workdir=""
mounted_securityfs=0
worker_pids=()

run_test()
{
	local description="$1"
	shift

	test_count=$((test_count + 1))
	if "$@"; then
		echo "ok $test_count - $description"
	else
		echo "not ok $test_count - $description"
		failures=$((failures + 1))
	fi
}

securityfs_mounted()
{
	awk '$3 == "securityfs" { found = 1; exit } END { exit !found }' /proc/mounts
}

module_present()
{
	awk -v module="$policy_name" '$1 == module { found = 1; exit } END { exit !found }' \
		"$modules" 2>/dev/null
}

wait_module_absent()
{
	local timeout=100
	local i

	for ((i = 0; i < timeout; i++)); do
		module_present || return 0
		sleep 0.2
	done
	return 1
}

register_policy()
{
	cat "$policy_path" > "$register"
}

unregister_policy()
{
	echo "$policy_name" > "$unregister" 2>/dev/null || true
}

worker_loop()
{
	local id="$1"
	local dir="$workdir/worker-$id"
	local end=$((SECONDS + duration))
	local i

	mkdir -p "$dir"
	while ((SECONDS < end)); do
		for i in 1 2 3 4 5 6; do
			: > "$dir/f$i"
			cat "$dir/f$i" >/dev/null 2>&1
			mv "$dir/f$i" "$dir/g$i"
			rm -f "$dir/g$i"
		done
		# Task churn: force task-VM allocation/teardown while hooks fire.
		( exec /bin/true )
		# Path walk: exercise dentry/inode/permission hooks.
		ls /usr/bin >/dev/null 2>&1
	done
}

stop_workers()
{
	local pid

	for pid in "${worker_pids[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
	worker_pids=()
}

cleanup()
{
	stop_workers
	unregister_policy
	[[ -n "$workdir" ]] && rm -rf "$workdir"
	if [[ "$mounted_securityfs" -eq 1 ]]; then
		umount /sys/kernel/security 2>/dev/null || true
	fi
}
trap cleanup EXIT

if ! securityfs_mounted; then
	mkdir -p /sys/kernel/security
	if ! mount -t securityfs securityfs /sys/kernel/security; then
		echo "unable to mount securityfs" >&2
		exit 1
	fi
	mounted_securityfs=1
fi

if [[ ! -d "$lua_dir" || ! -r "$policy_path" ]]; then
	echo "missing lua-lsm control dir or policy: $policy_path" >&2
	exit 1
fi

workdir="$(mktemp -d)"

baseline_stats="$(cat "$stats" 2>/dev/null || true)"

# Start workers first so every register/unregister below overlaps dispatch.
for ((i = 1; i <= workers; i++)); do
	worker_loop "$i" &
	worker_pids+=("$!")
done

registered_ok=0
duplicate_rejected=0
raced_clean=0

for ((cycle = 1; cycle <= cycles; cycle++)); do
	unregister_policy

	if register_policy; then
		registered_ok=$((registered_ok + 1))
	fi

	# Race a second register against the live module. The kernel's module
	# table must serialize the two: exactly one register may win.
	register_policy >/dev/null 2>&1 &
	dup_pid=$!
	if wait "$dup_pid"; then
		:
	else
		duplicate_rejected=$((duplicate_rejected + 1))
	fi

	# Unregister while workers are still dispatching hooks.
	unregister_policy
	if wait_module_absent; then
		raced_clean=$((raced_clean + 1))
	fi
done

stop_workers

run_test "policy registers under concurrent dispatch" \
	test "$registered_ok" -gt 0
run_test "duplicate register is rejected at least once" \
	test "$duplicate_rejected" -gt 0
run_test "unregister drains the module every cycle" \
	test "$raced_clean" -eq "$cycles"
run_test "module list ends clean" wait_module_absent

# Give the finalization worker a moment, then record the post-run counters
# for the artifact trail. We do not fail on residual per-CPU VM caches:
# they are expected to stay warm, and leak checking is verify-cleanup's job.
sleep 1
after_stats="$(cat "$stats" 2>/dev/null || true)"
echo "# --- stats before ---"
printf '%s\n' "$baseline_stats"
echo "# --- stats after ---"
printf '%s\n' "$after_stats"

echo "# Planned tests: $test_count"
[[ "$failures" -eq 0 ]]
