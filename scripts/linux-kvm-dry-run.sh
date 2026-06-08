#!/usr/bin/env bash
# Linux KVM dry-run handoff for lua-lsm-testsuite.
#
# The harness REFUSES to execute on macOS (planning-time guard on uname -s ==
# Darwin), so the live boot/SSH/workload/teardown path cannot be exercised
# from a Darwin dev host. This script is the copy-paste reproducible
# acceptance entry point a Linux KVM host runs to verify the harness end to
# end on real hardware.
#
# Operator workflow:
#   1. Validate host readiness without spawning the harness:
#        $ scripts/linux-kvm-dry-run.sh --prereqs-only
#      Fix any reported issues, then:
#   2. Run the full acceptance sequence:
#        $ scripts/linux-kvm-dry-run.sh
#
# Full-run steps (each prints the artifact paths to inspect at the end):
#   1. Smoke a single known-good cell (hello policy).
#   2. Run a bounded multi-cell smoke subset with distinct SSH ports.
#   3. Run one warmed-image UnixBench perf cell with denyfile (the hook-delta
#      acceptance proof: file_post_open.count must be > 0 in
#      result.json.perf).
#   4. Run one LKDTM positive-control cell; if CONFIG_LKDTM is missing the
#      classifier records skip:no-lkdtm and the script reports that
#      explicitly.
#   5. Exercise the host-env no-kvm code path on a host that DOES have
#      /dev/kvm, by setting LUA_LSM_TESTSUITE_KVM_PATH=/nonexistent for
#      that one step. The cell stays kvm_required=True (the default);
#      hostenv detection sees the bogus path and reports has_kvm=False,
#      which is the real input the cell_runner skip:no-kvm branch needs.
#      The earlier `--no-kvm` flag spelling was wrong: it sets
#      kvm_required=False, which BYPASSES the skip branch instead of
#      exercising it. The env override is the supported test hook for
#      this acceptance check.
#
# Required env vars (override as needed):
#   WORKSPACE   parent directory holding lua-lsm-tools/, kernel/linux/,
#               and lua-lsm-testsuite/ (default: /Volumes/DevWork,
#               which is the canonical layout; override on real Linux hosts).
#   KERNEL      path to the built bzImage.
#   ROOTFS      path to a Rocky9 (or compatible) rootfs image.
#
# Optional env vars:
#   RUNS_ROOT   where per-cell artifact directories land (default:
#               <workspace>/lua-lsm-testsuite/runs).
#   PORT_BASE   matrix port-base (default: 11000, far above the harness's
#               10023 default to avoid colliding with an interactive run).
#   PARALLEL    matrix parallelism (default: 2 -- bounded for a dry run).
#   LAUNCHER    absolute path to the vendored run_qemu_anolis.sh (default:
#               <workspace>/lua-lsm-testsuite/tools/run_qemu_anolis.sh).
#
# Artifact-path map per step (relative to the per-step latest run directory
# printed by show_artifacts):
#   Step 1 (smoke):    <cell-id>/{cell.json,serial.log,dmesg.log,
#                                 journalctl-kb.txt,workload-smoke.log,
#                                 result.json}
#   Step 2 (matrix):   matrix.json (at run root) and <cell-id>/{...same per
#                                 cell as Step 1, with distinct HOST_SSH_PORT
#                                 recorded in cell.json}
#   Step 3 (perf):     <cell-id>/{system.txt,command.txt,unixbench.log,
#                                 stats-before.txt,stats-after.txt,
#                                 lsm_funcs-before.txt,lsm_funcs-after.txt,
#                                 workload-unixbench.log,result.json,
#                                 results/<run-id>/}
#                      perf hook-delta proof (matches the harness schema in
#                      cell_runner._classify_and_finalize, where
#                      result["perf"] = {"snapshots": {"before","after"},
#                      "deltas": ...} and deltas are keyed under
#                      lsm_funcs.<hook>.count):
#                        result.json.perf.deltas.lsm_funcs.file_post_open.count
#                        must be > 0
#                      Equivalently, before/after raw counts live at:
#                        result.json.perf.snapshots.before.lsm_funcs.file_post_open.count
#                        result.json.perf.snapshots.after.lsm_funcs.file_post_open.count
#                      and after.count must exceed before.count.
#   Step 4 (lkdtm):    <cell-id>/{workload-lkdtm.log,result.json}
#                      verdict is kernel-bug (CONFIG_LKDTM present) or
#                      skip:no-lkdtm (absent).
#   Step 5 (no-kvm):   <cell-id>/{cell.json,result.json}
#                      result.json.verdict == "skip:no-kvm"; host.has_kvm
#                      should be false; no serial.log or dmesg.log because
#                      no QEMU spawn happened.
#
# Audit-trail log: when run without --prereqs-only, the script tees the
# full stdout+stderr to ${RUNS_ROOT}/dry-run-<UTC timestamp>.log so the
# operator's paste-back is unambiguous.
#
# This script is intentionally self-contained: it writes a tiny ad-hoc
# matrix config to a tempfile rather than depending on a checked-in subset.

set -euo pipefail

# ---- Arg parsing -----------------------------------------------------------

PREREQS_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --prereqs-only)
            PREREQS_ONLY=1
            ;;
        -h|--help)
            sed -n '2,80p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $arg" >&2
            echo "Usage: $0 [--prereqs-only|-h|--help]" >&2
            exit 2
            ;;
    esac
done

# ---- Env defaults ----------------------------------------------------------

WORKSPACE="${WORKSPACE:-/Volumes/DevWork}"
KERNEL="${KERNEL:-}"
ROOTFS="${ROOTFS:-}"
RUNS_ROOT="${RUNS_ROOT:-${WORKSPACE}/lua-lsm-testsuite/runs}"
PORT_BASE="${PORT_BASE:-11000}"
PARALLEL="${PARALLEL:-2}"
LAUNCHER="${LAUNCHER:-${WORKSPACE}/lua-lsm-testsuite/tools/run_qemu_anolis.sh}"

# ---- Precondition checks ---------------------------------------------------

# check_prereqs validates the host can run the dry-run end to end. It exits
# non-zero with an explicit diagnostic on every failure; on success it
# prints a one-line readiness summary so the operator can confirm the
# environment in their paste-back log.
#
# Failures (each writes to stderr and exits 2):
#   - Host is Darwin (the harness refuses to plan).
#   - KERNEL or ROOTFS env vars missing.
#   - WORKSPACE does not contain the sibling lua-lsm-tools/ and kernel/linux/
#     checkouts plus the harness repo.
#   - KERNEL or ROOTFS files do not exist or are not readable.
#   - /dev/kvm is missing (steps 1-4 cannot succeed; step 5 alone could
#     still run, but a host without /dev/kvm is not a complete dry-run host).
check_prereqs() {
    if [ "$(uname -s)" = "Darwin" ]; then
        echo "ERROR: this dry-run script must run on a Linux KVM host." >&2
        echo "       The harness itself REFUSES to plan on macOS." >&2
        return 2
    fi

    if [ -z "${KERNEL}" ] || [ -z "${ROOTFS}" ]; then
        echo "ERROR: KERNEL and ROOTFS env vars are required." >&2
        echo "Usage: WORKSPACE=/path KERNEL=/path/to/bzImage ROOTFS=/path/to/rootfs.img $0" >&2
        return 2
    fi

    if [ ! -d "${WORKSPACE}/lua-lsm-tools" ] || [ ! -d "${WORKSPACE}/kernel/linux" ]; then
        echo "ERROR: WORKSPACE ${WORKSPACE} does not contain lua-lsm-tools/ and kernel/linux/." >&2
        echo "       This script expects the canonical sibling-checkout layout." >&2
        return 2
    fi

    if [ ! -d "${WORKSPACE}/lua-lsm-testsuite" ]; then
        echo "ERROR: WORKSPACE ${WORKSPACE} does not contain lua-lsm-testsuite/." >&2
        return 2
    fi

    if [ ! -r "${LAUNCHER}" ] || [ ! -x "${LAUNCHER}" ]; then
        echo "ERROR: LAUNCHER=${LAUNCHER} is not a readable+executable file." >&2
        echo "       Override LAUNCHER=/abs/path/to/run_qemu_anolis.sh if needed." >&2
        return 2
    fi

    if [ ! -r "${KERNEL}" ]; then
        echo "ERROR: KERNEL=${KERNEL} is not a readable file." >&2
        return 2
    fi

    if [ ! -r "${ROOTFS}" ]; then
        echo "ERROR: ROOTFS=${ROOTFS} is not a readable file." >&2
        return 2
    fi

    if [ ! -e /dev/kvm ]; then
        echo "ERROR: /dev/kvm is missing. Steps 1-4 require KVM acceleration." >&2
        echo "       Only step 5 (skip:no-kvm acceptance proof) can run without" >&2
        echo "       /dev/kvm, and that is not the intent of this dry-run." >&2
        return 2
    fi

    # Readability is a separate fence -- /dev/kvm existing but unreadable to
    # the current user is a common operator misconfiguration (missing kvm
    # group membership). Catch it here with a remediation hint.
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        echo "ERROR: /dev/kvm exists but is not readable+writable by $(id -un)." >&2
        echo "       Add the user to the kvm group (or re-run as root) and try again." >&2
        return 2
    fi

    echo "[prereqs] host=$(uname -s) kernel=${KERNEL} rootfs=${ROOTFS} workspace=${WORKSPACE} launcher=${LAUNCHER} /dev/kvm=present"
    return 0
}

check_prereqs

if [ "${PREREQS_ONLY}" -eq 1 ]; then
    echo "[prereqs] OK -- host is ready for the full dry-run."
    echo "[prereqs] Next: $0  (drop the --prereqs-only flag to execute steps 1-5)."
    exit 0
fi

# ---- Audit-trail tee log ---------------------------------------------------

mkdir -p "${RUNS_ROOT}"
DRY_RUN_LOG="${RUNS_ROOT}/dry-run-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "${DRY_RUN_LOG}") 2>&1
echo "[audit] full script output is tee'd to ${DRY_RUN_LOG}"

# ---- Setup -----------------------------------------------------------------

cd "${WORKSPACE}/lua-lsm-testsuite"

PY="${PY:-python3}"
TMP_CONFIG="$(mktemp -t lua-lsm-dryrun-matrix.XXXXXX.json)"
trap 'rm -f "${TMP_CONFIG}"' EXIT

banner() {
    printf '\n========== %s ==========\n' "$*"
}

show_artifacts() {
    local step="$1"
    echo
    echo "[${step}] latest artifact directory:"
    # The harness writes per-run trees under RUNS_ROOT named with a UTC
    # timestamp; surface the newest one so the operator knows where to look.
    if [ -d "${RUNS_ROOT}" ]; then
        ls -1dt "${RUNS_ROOT}"/*/ 2>/dev/null | head -1 || echo "  (no runs/ entries yet)"
    else
        echo "  (RUNS_ROOT ${RUNS_ROOT} does not exist yet)"
    fi
}

# ---- Step 1: single-cell smoke --------------------------------------------

banner "Step 1/5: single-cell smoke (hello policy)"
"${PY}" -m harness run \
    --kernel "${KERNEL}" \
    --rootfs "${ROOTFS}" \
    --launcher "${LAUNCHER}" \
    --share-dir "${WORKSPACE}" \
    --workload smoke \
    --policy hello \
    --kconfig-profile standard \
    --runs-root "${RUNS_ROOT}" \
    --headless
show_artifacts "step1-smoke"

# ---- Step 2: bounded multi-cell matrix ------------------------------------

banner "Step 2/5: bounded multi-cell smoke matrix (4 cells)"
cat > "${TMP_CONFIG}" <<'JSON'
{
  "name": "dryrun-bounded",
  "workload": "smoke",
  "defaults": {
    "kvm_required": true,
    "kconfig_profile": "standard",
    "kind": "bughunt"
  },
  "axes": {
    "policy": ["hello", "denyfile"],
    "lvm_pool_max": [0, 32]
  },
  "exclude": []
}
JSON
"${PY}" -m harness matrix \
    --config "${TMP_CONFIG}" \
    --kernel "${KERNEL}" \
    --rootfs "${ROOTFS}" \
    --launcher "${LAUNCHER}" \
    --share-dir "${WORKSPACE}" \
    --port-base "${PORT_BASE}" \
    --parallel "${PARALLEL}" \
    --runs-root "${RUNS_ROOT}" \
    --tap
show_artifacts "step2-matrix"

# ---- Step 3: warmed-image UnixBench perf cell -----------------------------

banner "Step 3/5: warm rootfs marker for image"
"${PY}" -m harness image-warm --image "${ROOTFS}"

banner "Step 3/5: UnixBench perf cell (denyfile) -- hook-delta acceptance proof"
"${PY}" -m harness run \
    --kernel "${KERNEL}" \
    --rootfs "${ROOTFS}" \
    --launcher "${LAUNCHER}" \
    --share-dir "${WORKSPACE}" \
    --workload unixbench \
    --policy denyfile \
    --kind perf \
    --kconfig-profile standard \
    --runs-root "${RUNS_ROOT}" \
    --workload-timeout 3600 \
    --headless
show_artifacts "step3-perf"
echo
echo "[step3-perf] hook-delta proof lives at:"
echo "             result.json.perf.deltas.lsm_funcs.file_post_open.count > 0"
echo "             (equivalently: snapshots.after.lsm_funcs.file_post_open.count"
echo "             must exceed snapshots.before.lsm_funcs.file_post_open.count)."

# ---- Step 4: LKDTM positive control ---------------------------------------

banner "Step 4/5: LKDTM positive-control cell"
LKDTM_RC=0
"${PY}" -m harness run \
    --kernel "${KERNEL}" \
    --rootfs "${ROOTFS}" \
    --launcher "${LAUNCHER}" \
    --share-dir "${WORKSPACE}" \
    --workload lkdtm \
    --kconfig-profile standard \
    --runs-root "${RUNS_ROOT}" \
    --headless || LKDTM_RC=$?
show_artifacts "step4-lkdtm"
if [ "${LKDTM_RC}" -ne 0 ]; then
    echo "[step4-lkdtm] non-zero exit ${LKDTM_RC}: inspect result.json.verdict."
    echo "             expected verdict for a kernel WITHOUT CONFIG_LKDTM: skip:no-lkdtm"
    echo "             expected verdict for a kernel WITH CONFIG_LKDTM:    kernel-bug (positive control)"
fi

# ---- Step 5: skip:no-kvm via env-controlled hostenv override --------------

banner "Step 5/5: skip:no-kvm via LUA_LSM_TESTSUITE_KVM_PATH override"
NOKVM_RC=0
LUA_LSM_TESTSUITE_KVM_PATH=/nonexistent/kvm/path \
"${PY}" -m harness run \
    --kernel "${KERNEL}" \
    --rootfs "${ROOTFS}" \
    --launcher "${LAUNCHER}" \
    --share-dir "${WORKSPACE}" \
    --workload smoke \
    --policy hello \
    --kconfig-profile standard \
    --runs-root "${RUNS_ROOT}" \
    --headless || NOKVM_RC=$?
show_artifacts "step5-no-kvm"
echo "[step5-no-kvm] expected verdict: skip:no-kvm (the cell records the skip"
echo "               without booting the VM, exit ${NOKVM_RC} from the CLI)."
echo "               Mechanism: kvm_required stays True (default); the env"
echo "               override makes hostenv detection report no /dev/kvm."

# ---- Summary --------------------------------------------------------------

banner "Dry run complete"
echo "All five steps executed. Inspect the per-step artifact directories"
echo "printed above. The hook-delta acceptance proof lives in step3-perf:"
echo "  jq '.perf | {"
echo "        before: .snapshots.before.lsm_funcs.file_post_open.count,"
echo "        after:  .snapshots.after.lsm_funcs.file_post_open.count,"
echo "        delta:  .deltas.lsm_funcs.file_post_open.count"
echo "     }' \\"
echo "     ${RUNS_ROOT}/<latest>/<cell>/result.json"
echo
echo "Audit-trail log: ${DRY_RUN_LOG}"
