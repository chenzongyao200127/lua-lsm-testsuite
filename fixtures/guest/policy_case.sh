#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Single-policy regression case for Lua-LSM.
#
# Registers POLICY_PATH, verifies it is visible with at least the expected
# shape, exercises a default file workload so the policy's hooks dispatch,
# optionally runs a companion assertion script (POLICY_PATH with the .lua
# suffix replaced by .sh), then unregisters and verifies the module list is
# clean.
#
# Usage: policy_case.sh POLICY_PATH
#
# The companion script runs with the policy active and must exit non-zero
# on failure; its stdout/stderr are forwarded into the workload log.

set -u

policy_path="${1:?usage: policy_case.sh POLICY_PATH}"
companion="${policy_path%.lua}.sh"

lua_dir=/sys/kernel/security/lua
register="$lua_dir/register"
unregister="$lua_dir/unregister"
modules="$lua_dir/modules"

policy_name="$(basename -- "$policy_path")"
policy_name="${policy_name%.lua}"

test_count=0
failures=0
mounted_securityfs=0
workdir=""

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

module_field()
{
	local module="$1"
	local field="$2"

	awk -v module="$module" -v field="$field" '
		$1 == module { print $field; exit }
	' "$modules" 2>/dev/null
}

module_present()
{
	awk -v module="$policy_name" '$1 == module { found = 1; exit } END { exit !found }' \
		"$modules" 2>/dev/null
}

# A module is also mapped into the Lua VM of every task that ran a hook, and
# those VMs drain asynchronously when their tasks exit. Unregister then answers
# EBUSY and leaves the module as a zombie; a later write finishes the job, so
# retry until the module list converges instead of assuming one-shot success.
unregister_policy()
{
	local i

	for ((i = 0; i < 150; i++)); do
		module_present || return 0
		echo "$policy_name" > "$unregister" 2>/dev/null
		sleep 0.2
	done
	module_present && return 1
	return 0
}

cleanup()
{
	echo "$policy_name" > "$unregister" 2>/dev/null || true
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

check_absent()
{
	! module_present
}

check_present()
{
	module_present
}

register_policy()
{
	cat "$policy_path" > "$register"
}

check_metadata()
{
	local hooks

	hooks="$(module_field "$policy_name" 4)"
	[[ "$hooks" =~ ^[0-9]+$ ]]
}

# Default exercise: touch the file/permission/exec hook paths so a policy
# that implements them actually dispatches while registered.
exercise_default()
{
	echo data > "$workdir/probe"
	cat "$workdir/probe" >/dev/null
	ls /usr/bin >/dev/null
	return 0
}

run_test "policy is initially absent" check_absent
run_test "policy registers" register_policy
run_test "policy is visible in module list" check_present
run_test "module metadata is readable" check_metadata
run_test "default file/task exercise succeeds" exercise_default

if [[ -r "$companion" ]]; then
	echo "# --- companion: $companion"
	if bash "$companion"; then
		run_test "companion assertions pass" true
	else
		run_test "companion assertions pass" false
	fi
fi

run_test "policy unregisters" unregister_policy
run_test "module list ends clean" check_absent

echo "# Planned tests: $test_count"
[[ "$failures" -eq 0 ]]
