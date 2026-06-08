#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [--help]

Start a local x86_64 kernel debug VM.

Environment variables:
  VM_NAME            QEMU VM name
                     Default: kernel-dev
  KERNEL_IMG         Kernel bzImage path
                     Default: ${REPO_ROOT}/../cloud-kernel/arch/x86/boot/bzImage
  INITRD_IMG         Optional initrd image path
                     Default: unset
  ROOTFS_IMG         Guest rootfs image path
                     Default: ${REPO_ROOT}/tools/rocky9-selinux-rootfs.qcow2
                     Fallback: ${REPO_ROOT}/tools/test_lua_lsm.qcow2
  ROOT_DEV           Guest root block device passed on cmdline
                     Default: /dev/vda
  CONSOLE            Guest serial console passed on cmdline
                     Default: ttyS0
  KERNEL_CMDLINE     Full kernel cmdline override
                     Default: root=\${ROOT_DEV} rw console=\${CONSOLE} nokaslr systemd.hostname=\${SYSTEM_HOSTNAME}
  EXTRA_CMDLINE      Extra kernel cmdline appended after the default cmdline
                     Default: unset
  SHARE_DIR          Host directory shared into guest via 9p
                     Default: ${REPO_ROOT}/..
  ENABLE_SHARE       Enable 9p shared directory: 1 or 0
                     Default: 1
  SHARE_TAG          9p mount tag exposed to guest
                     Default: host_share
  GUEST_SHARE_MOUNT  Guest mountpoint description shown in logs
                     Default: /mnt/host
  MEM_SIZE           Guest memory size
                     Default: 32G
  SMP_COUNT          Guest vCPU count
                     Default: 32
  NET_MODE           Guest networking mode: user, tap, or none
                     Default: user
  HOST_SSH_PORT      Host TCP port forwarded to guest 22
                     Default: 10023
  EXTRA_HOSTFWD      Extra QEMU user-mode hostfwd rules, comma-separated
                     Default: unset
  TAP_IFNAME         Host tap interface when NET_MODE=tap
                     Default: tap0
  TAP_SCRIPT         QEMU tap up script when NET_MODE=tap
                     Default: no
  TAP_DOWNSCRIPT     QEMU tap down script when NET_MODE=tap
                     Default: no
  NET_DEVICE_MODEL   Guest NIC device model
                     Default: virtio-net-pci
  NET_DEVICE_EXTRA_OPTS
                     Extra NIC device options appended after netdev=net0
                     Default: mq=on,vectors=<derived from SMP_COUNT>
  QEMU_BIN           QEMU binary
                     Default: qemu-system-x86_64
  QEMU_ACCEL         QEMU accelerator
                     Default: kvm
  CPU_MODEL          QEMU CPU model
                     Default: host
  MACHINE_TYPE       QEMU machine type
                     Default: q35
  DISK_CACHE         QEMU disk cache mode
                     Default: none
  DISK_AIO           QEMU disk AIO mode
                     Default: native
  SYSTEM_HOSTNAME    Guest hostname passed on kernel cmdline
                     Default: kernel-dev-box
  ENABLE_GDB         Enable QEMU gdb stub: 1 or 0
                     Default: 0
  GDB_PORT           GDB TCP port when ENABLE_GDB=1
                     Default: 1235
  DEBUG_WAIT         Pause guest at startup with -S: 1 or 0
                     Default: 0
  QEMU_PIDFILE       Optional QEMU pidfile path
                     Default: unset
  QEMU_MONITOR_SOCK  Optional QEMU monitor Unix socket path
                     Default: unset
  QEMU_EXTRA_ARGS    Extra QEMU arguments appended at the end
                     Default: unset

Examples:
  $(basename "$0")
  ROOTFS_IMG=${REPO_ROOT}/tools/rocky9-selinux-rootfs.qcow2 $(basename "$0")
  QEMU_ACCEL=tcg CPU_MODEL=max $(basename "$0")
  ENABLE_GDB=0 HOST_SSH_PORT=10024 $(basename "$0")
  INITRD_IMG=./initramfs.img $(basename "$0")
  NET_MODE=tap TAP_IFNAME=tap0 $(basename "$0")
  QEMU_EXTRA_ARGS="-object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0" $(basename "$0")
  EXTRA_CMDLINE="selinux=1 enforcing=0 lsm=capability,yama,lua,selinux,bpf,integrity" $(basename "$0")
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

DEFAULT_KERNEL_IMG="${REPO_ROOT}/../cloud-kernel/arch/x86/boot/bzImage"
DEFAULT_ROOTFS_IMG="${REPO_ROOT}/tools/rocky9-selinux-rootfs.qcow2"
if [[ ! -e "${DEFAULT_ROOTFS_IMG}" ]]; then
    DEFAULT_ROOTFS_IMG="${REPO_ROOT}/tools/test_lua_lsm.qcow2"
fi

KERNEL_IMG="${KERNEL_IMG:-${DEFAULT_KERNEL_IMG}}"
INITRD_IMG="${INITRD_IMG:-}"
ROOTFS_IMG="${ROOTFS_IMG:-${DEFAULT_ROOTFS_IMG}}"
SHARE_DIR="${SHARE_DIR:-${REPO_ROOT}/..}"
ENABLE_SHARE="${ENABLE_SHARE:-1}"
SHARE_TAG="${SHARE_TAG:-host_share}"
GUEST_SHARE_MOUNT="${GUEST_SHARE_MOUNT:-/mnt/host}"

MEM_SIZE="${MEM_SIZE:-32G}"
SMP_COUNT="${SMP_COUNT:-32}"
HOST_SSH_PORT="${HOST_SSH_PORT:-10023}"
NET_MODE="${NET_MODE:-user}"
EXTRA_HOSTFWD="${EXTRA_HOSTFWD:-}"
TAP_IFNAME="${TAP_IFNAME:-tap0}"
TAP_SCRIPT="${TAP_SCRIPT:-no}"
TAP_DOWNSCRIPT="${TAP_DOWNSCRIPT:-no}"
NET_DEVICE_MODEL="${NET_DEVICE_MODEL:-virtio-net-pci}"
NET_DEVICE_EXTRA_OPTS="${NET_DEVICE_EXTRA_OPTS:-mq=on,vectors=$((SMP_COUNT * 2 + 2))}"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
QEMU_ACCEL="${QEMU_ACCEL:-kvm}"
CPU_MODEL="${CPU_MODEL:-host}"
MACHINE_TYPE="${MACHINE_TYPE:-q35}"
DISK_CACHE="${DISK_CACHE:-none}"
DISK_AIO="${DISK_AIO:-native}"
VM_NAME="${VM_NAME:-kernel-dev}"
SYSTEM_HOSTNAME="${SYSTEM_HOSTNAME:-kernel-dev-box}"
ROOT_DEV="${ROOT_DEV:-/dev/vda}"
CONSOLE="${CONSOLE:-ttyS0}"
KERNEL_CMDLINE="${KERNEL_CMDLINE:-}"
EXTRA_CMDLINE="${EXTRA_CMDLINE:-}"
QEMU_PIDFILE="${QEMU_PIDFILE:-}"
QEMU_MONITOR_SOCK="${QEMU_MONITOR_SOCK:-}"
QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:-}"

ENABLE_GDB="${ENABLE_GDB:-0}"
GDB_PORT="${GDB_PORT:-1235}"
DEBUG_WAIT="${DEBUG_WAIT:-0}"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing command: $1" >&2
        exit 1
    }
}

require_path() {
    local path="$1"
    local label="$2"

    if [[ ! -e "${path}" ]]; then
        echo "${label} not found: ${path}" >&2
        exit 1
    fi
}

detect_rootfs_format() {
    case "$1" in
        *.raw|*.img)
            echo "raw"
            ;;
        *)
            echo "qcow2"
            ;;
    esac
}

require_cmd "${QEMU_BIN}"
require_path "${KERNEL_IMG}" "kernel image"
require_path "${ROOTFS_IMG}" "rootfs image"

if [[ -n "${INITRD_IMG}" ]]; then
    require_path "${INITRD_IMG}" "initrd image"
fi

if [[ "${ENABLE_SHARE}" == "1" ]]; then
    require_path "${SHARE_DIR}" "share directory"
fi

ROOTFS_FORMAT="$(detect_rootfs_format "${ROOTFS_IMG}")"

if [[ "${QEMU_ACCEL}" == "kvm" && ( ! -e /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ) ]]; then
    echo "warning: /dev/kvm is unavailable or inaccessible, falling back to tcg" >&2
    QEMU_ACCEL="tcg"
fi

if [[ "${QEMU_ACCEL}" != "kvm" && "${CPU_MODEL}" == "host" ]]; then
    CPU_MODEL="max"
fi

if [[ -z "${KERNEL_CMDLINE}" ]]; then
    CMDLINE_ARGS=(
        "root=${ROOT_DEV}"
        "rw"
        "console=${CONSOLE}"
        "nokaslr"
        "systemd.hostname=${SYSTEM_HOSTNAME}"
    )
    CMDLINE="${CMDLINE_ARGS[*]}"
else
    CMDLINE="${KERNEL_CMDLINE}"
fi

if [[ -n "${EXTRA_CMDLINE}" ]]; then
    CMDLINE="${CMDLINE} ${EXTRA_CMDLINE}"
fi

QEMU_ARGS=(
    -name "${VM_NAME}"
    -machine "${MACHINE_TYPE},accel=${QEMU_ACCEL}"
    -nographic
    -cpu "${CPU_MODEL}"
    -m "${MEM_SIZE}"
    -smp "${SMP_COUNT},sockets=1,cores=${SMP_COUNT},threads=1"
    -kernel "${KERNEL_IMG}"
    -append "${CMDLINE}"
    -drive "file=${ROOTFS_IMG},format=${ROOTFS_FORMAT},if=none,id=hd0,cache=${DISK_CACHE},aio=${DISK_AIO}"
    -device "virtio-blk-pci,drive=hd0,num-queues=${SMP_COUNT}"
)

if [[ -n "${INITRD_IMG}" ]]; then
    QEMU_ARGS+=(-initrd "${INITRD_IMG}")
fi

NET_DEVICE="${NET_DEVICE_MODEL},netdev=net0"
if [[ -n "${NET_DEVICE_EXTRA_OPTS}" ]]; then
    NET_DEVICE="${NET_DEVICE},${NET_DEVICE_EXTRA_OPTS}"
fi

case "${NET_MODE}" in
    user)
        USER_NETDEV="user,id=net0,hostfwd=tcp::${HOST_SSH_PORT}-:22"
        if [[ -n "${EXTRA_HOSTFWD}" ]]; then
            USER_NETDEV="${USER_NETDEV},${EXTRA_HOSTFWD}"
        fi
        QEMU_ARGS+=(
            -netdev "${USER_NETDEV}"
            -device "${NET_DEVICE}"
        )
        ;;
    tap)
        QEMU_ARGS+=(
            -netdev "tap,id=net0,ifname=${TAP_IFNAME},script=${TAP_SCRIPT},downscript=${TAP_DOWNSCRIPT}"
            -device "${NET_DEVICE}"
        )
        ;;
    none)
        ;;
    *)
        echo "unsupported NET_MODE: ${NET_MODE}" >&2
        echo "supported values: user, tap, none" >&2
        exit 1
        ;;
esac

if [[ "${ENABLE_SHARE}" == "1" ]]; then
    QEMU_ARGS+=(
        -fsdev "local,security_model=passthrough,id=fsdev0,path=${SHARE_DIR}"
        -device "virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=${SHARE_TAG}"
    )
fi

if [[ "${ENABLE_GDB}" == "1" ]]; then
    QEMU_ARGS+=(-gdb "tcp::${GDB_PORT}")
fi

if [[ "${DEBUG_WAIT}" == "1" ]]; then
    QEMU_ARGS+=(-S)
fi

if [[ -n "${QEMU_PIDFILE}" ]]; then
    QEMU_ARGS+=(-pidfile "${QEMU_PIDFILE}")
fi

if [[ -n "${QEMU_MONITOR_SOCK}" ]]; then
    QEMU_ARGS+=(-monitor "unix:${QEMU_MONITOR_SOCK},server,nowait")
fi

if [[ -n "${QEMU_EXTRA_ARGS}" ]]; then
    read -r -a QEMU_EXTRA_ARGS_ARR <<< "${QEMU_EXTRA_ARGS}"
    QEMU_ARGS+=("${QEMU_EXTRA_ARGS_ARR[@]}")
fi

echo "Starting QEMU..."
echo "  QEMU: ${QEMU_BIN}"
echo "  Kernel: ${KERNEL_IMG}"
echo "  RootFS: ${ROOTFS_IMG} (${ROOTFS_FORMAT})"
echo "  Accel: ${QEMU_ACCEL}"
echo "  CPU: ${CPU_MODEL} (${SMP_COUNT} vCPUs)"
echo "  RAM: ${MEM_SIZE}"
echo "  Net: ${NET_MODE}"
if [[ "${NET_MODE}" == "user" ]]; then
    echo "  SSH: localhost:${HOST_SSH_PORT} -> guest:22"
elif [[ "${NET_MODE}" == "tap" ]]; then
    echo "  Tap: ${TAP_IFNAME} (${NET_DEVICE_MODEL})"
fi
if [[ "${ENABLE_SHARE}" == "1" ]]; then
    echo "  Share: ${SHARE_DIR} <--> ${GUEST_SHARE_MOUNT} (tag ${SHARE_TAG})"
else
    echo "  Share: disabled"
fi
if [[ -n "${INITRD_IMG}" ]]; then
    echo "  Initrd: ${INITRD_IMG}"
fi
echo "  Disk: cache=${DISK_CACHE} aio=${DISK_AIO}"
echo "  GDB: ${ENABLE_GDB} (port ${GDB_PORT})"
echo "  Debug wait: ${DEBUG_WAIT}"
echo "  Cmdline: ${CMDLINE}"
if [[ -n "${QEMU_PIDFILE}" ]]; then
    echo "  Pidfile: ${QEMU_PIDFILE}"
fi
if [[ -n "${QEMU_MONITOR_SOCK}" ]]; then
    echo "  Monitor: ${QEMU_MONITOR_SOCK}"
fi
if [[ -n "${QEMU_EXTRA_ARGS}" ]]; then
    echo "  Extra QEMU args: ${QEMU_EXTRA_ARGS}"
fi
echo "  Tip: EXTRA_CMDLINE=\"selinux=1 enforcing=0 lsm=capability,yama,lua,selinux,bpf,integrity\" ${0}"

exec "${QEMU_BIN}" "${QEMU_ARGS[@]}"
