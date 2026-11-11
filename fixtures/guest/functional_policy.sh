#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -u

script_dir="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
policies_dir="$script_dir/../policies"
test_count=0
result=0
mounted_securityfs=0
workdir=""

cleanup()
{
	if [[ -n "$workdir" ]]; then
		if [[ -f /sys/kernel/security/lua/modules ]] &&
		   grep -q '^smoke ' /sys/kernel/security/lua/modules 2>/dev/null; then
			echo smoke > /sys/kernel/security/lua/unregister 2>/dev/null || true
		fi
		rm -rf "$workdir"
	fi
	if [[ "$mounted_securityfs" -eq 1 ]]; then
		umount /sys/kernel/security 2>/dev/null || true
	fi
}
trap cleanup EXIT

run_test()
{
	local description="$1"
	shift

	test_count=$((test_count + 1))
	if "$@"; then
		echo "ok $test_count - $description"
	else
		echo "not ok $test_count - $description"
		result=1
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
	' /sys/kernel/security/lua/modules
}

policy_load()
{
	cat "$policies_dir/$1.lua" > /sys/kernel/security/lua/register
}

policy_unload()
{
	echo "$1" > /sys/kernel/security/lua/unregister
}

check_control_files()
{
	[[ -f /sys/kernel/security/lua/version &&
	   -w /sys/kernel/security/lua/register &&
	   -w /sys/kernel/security/lua/unregister &&
	   -f /sys/kernel/security/lua/modules ]]
}

check_version()
{
	[[ "$(cat /sys/kernel/security/lua/version)" =~ ^[0-9]+$ ]]
}

check_initial_modules()
{
	! grep -q '^smoke ' /sys/kernel/security/lua/modules
}

check_valid_load()
{
	policy_load smoke
	grep -q '^smoke ' /sys/kernel/security/lua/modules
}

check_registered_hook()
{
	[[ "$(module_field smoke 4)" == "1" ]]
}

check_dispatch()
{
	local dispatch_file="$workdir/dispatch"
	local loads

	echo data > "$dispatch_file"
	loads="$(module_field smoke 5)"
	[[ "$loads" =~ ^[0-9]+$ && "$loads" -gt 0 ]]
}

check_duplicate_rejected()
{
	! policy_load smoke
}

check_invalid_rejected()
{
	! policy_load invalid
}

check_unload()
{
	local timeout=10
	local elapsed

	for ((elapsed = 0; elapsed < timeout; elapsed++)); do
		policy_unload smoke || true
		if ! grep -q '^smoke ' /sys/kernel/security/lua/modules; then
			return 0
		fi
		sleep 1
	done

	return 1
}

if ! securityfs_mounted; then
	mkdir -p /sys/kernel/security
	if ! mount -t securityfs securityfs /sys/kernel/security; then
		echo "unable to mount securityfs" >&2
		exit 1
	fi
	mounted_securityfs=1
fi

if [[ ! -d /sys/kernel/security/lua ]]; then
	echo "Lua-LSM securityfs directory is missing" >&2
	exit 1
fi

workdir="$(mktemp -d)"

run_test "Lua-LSM control files exist" check_control_files
run_test "Lua-LSM version is readable" check_version
run_test "smoke policy is initially absent" check_initial_modules
run_test "valid policy loads" check_valid_load
run_test "valid policy registers one hook" check_registered_hook
run_test "file permission dispatch builds a Lua VM" check_dispatch
run_test "duplicate policy is rejected" check_duplicate_rejected
run_test "invalid policy is rejected" check_invalid_rejected
run_test "policy unloads" check_unload

echo "# Planned tests: $test_count"
exit "$result"
