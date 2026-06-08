#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [--help]

Build a Rocky Linux 9 rootfs image for kernel development and debugging.

Environment variables:
  RAW_IMAGE          Output raw image path
                     Default: ${SCRIPT_DIR}/rocky9-selinux-rootfs.raw
  OUTPUT_IMAGE       Output qcow2 image path
                     Default: ${SCRIPT_DIR}/rocky9-selinux-rootfs.qcow2
  IMAGE_SIZE         Guest disk size
                     Default: 48G
  MOUNT_POINT        Temporary mountpoint for image build
                     Default: auto-created temp dir
  ROCKY_RELEASE      Rocky major release
                     Default: 9
  ARCH               Guest architecture
                     Default: x86_64
  ROCKY_MIRROR       Rocky mirror root
                     Default: https://download.rockylinux.org/pub/rocky
  VM_HOSTNAME        Guest hostname
                     Default: kernel-dev-box
  ROOT_PASSWORD      Root password
                     Default: root
  SSH_PUBKEY         SSH public key injected into /root/.ssh/authorized_keys
                     Default: \$HOME/.ssh/id_ed25519.pub
  SHARE_TAG          9p share tag written into /etc/fstab
                     Default: host_share
  GUEST_SHARE_MOUNT  Guest mountpoint for the host share
                     Default: /mnt/host
  SELINUX_MODE       enforcing, permissive, or disabled
                     Default: permissive
  ENABLE_AUTORELABEL Create /.autorelabel on first boot: 1 or 0
                     Default: 1
  INSTALL_DOCS       Keep man pages and package docs: 1 or 0
                     Default: 1
  EXTRA_PACKAGES     Extra packages appended to the install list
                     Default: unset
  FORCE              Overwrite existing output images: 1 or 0
                     Default: 0

Examples:
  $(basename "$0")
  IMAGE_SIZE=64G $(basename "$0")
  ROOT_PASSWORD=debug123 SELINUX_MODE=enforcing $(basename "$0")
  EXTRA_PACKAGES="rsyslog podman" $(basename "$0")
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

RAW_IMAGE="${RAW_IMAGE:-${SCRIPT_DIR}/rocky9-selinux-rootfs.raw}"
OUTPUT_IMAGE="${OUTPUT_IMAGE:-${SCRIPT_DIR}/rocky9-selinux-rootfs.qcow2}"
IMAGE_SIZE="${IMAGE_SIZE:-48G}"
MOUNT_POINT="${MOUNT_POINT:-}"

ROCKY_RELEASE="${ROCKY_RELEASE:-9}"
ARCH="${ARCH:-x86_64}"
ROCKY_MIRROR="${ROCKY_MIRROR:-https://download.rockylinux.org/pub/rocky}"

VM_HOSTNAME="${VM_HOSTNAME:-kernel-dev-box}"
ROOT_PASSWORD="${ROOT_PASSWORD:-root}"
SSH_PUBKEY="${SSH_PUBKEY:-${HOME}/.ssh/id_ed25519.pub}"
SHARE_TAG="${SHARE_TAG:-host_share}"
GUEST_SHARE_MOUNT="${GUEST_SHARE_MOUNT:-/mnt/host}"
SELINUX_MODE="${SELINUX_MODE:-permissive}"
ENABLE_AUTORELABEL="${ENABLE_AUTORELABEL:-1}"
INSTALL_DOCS="${INSTALL_DOCS:-1}"
EXTRA_PACKAGES="${EXTRA_PACKAGES:-}"
FORCE="${FORCE:-0}"

TMPDIR_CREATED=""
SUDO_KEEPALIVE=""
MOUNT_POINT_CREATED="0"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing command: $1" >&2
        exit 1
    }
}

merge_packages() {
    local pkg
    declare -A seen=()
    PACKAGES=()

    for pkg in "$@"; do
        [[ -n "${pkg}" ]] || continue
        if [[ -n "${seen[$pkg]+x}" ]]; then
            continue
        fi
        seen["$pkg"]=1
        PACKAGES+=("${pkg}")
    done
}

cleanup() {
    set +e

    if [[ -n "${SUDO_KEEPALIVE}" ]]; then
        kill "${SUDO_KEEPALIVE}" >/dev/null 2>&1 || true
    fi

    if [[ -n "${MOUNT_POINT}" ]] && mountpoint -q "${MOUNT_POINT}"; then
        sudo umount "${MOUNT_POINT}" || true
    fi

    if [[ "${MOUNT_POINT_CREATED}" == "1" && -n "${MOUNT_POINT}" && -d "${MOUNT_POINT}" ]]; then
        rmdir "${MOUNT_POINT}" >/dev/null 2>&1 || true
    fi

    if [[ -n "${TMPDIR_CREATED}" && -d "${TMPDIR_CREATED}" ]]; then
        rm -rf "${TMPDIR_CREATED}"
    fi
}

trap cleanup EXIT

for cmd in dnf qemu-img mkfs.ext4 mount mountpoint chroot install sed grep sudo; do
    require_cmd "${cmd}"
done

if [[ "${FORCE}" != "1" ]]; then
    for path in "${RAW_IMAGE}" "${OUTPUT_IMAGE}"; do
        if [[ -e "${path}" ]]; then
            echo "refusing to overwrite existing file: ${path}" >&2
            echo "set FORCE=1 to overwrite" >&2
            exit 1
        fi
    done
fi

echo "Refreshing sudo credentials..."
sudo -v
( while true; do sleep 30; sudo -n true; done ) >/dev/null 2>&1 &
SUDO_KEEPALIVE=$!

TMPDIR_CREATED="$(mktemp -d)"
REPO_DIR="${TMPDIR_CREATED}/repos"
mkdir -p "${REPO_DIR}"

if [[ -z "${MOUNT_POINT}" ]]; then
    MOUNT_POINT="${TMPDIR_CREATED}/mnt"
    MOUNT_POINT_CREATED="1"
fi

case "${SELINUX_MODE}" in
    enforcing|permissive|disabled)
        ;;
    *)
        echo "unsupported SELINUX_MODE: ${SELINUX_MODE}" >&2
        echo "supported values: enforcing, permissive, disabled" >&2
        exit 1
        ;;
esac

case "${INSTALL_DOCS}" in
    0|1)
        ;;
    *)
        echo "unsupported INSTALL_DOCS: ${INSTALL_DOCS}" >&2
        echo "supported values: 0, 1" >&2
        exit 1
        ;;
esac

cat > "${REPO_DIR}/rocky-bootstrap.repo" <<EOF
[rocky-baseos]
name=rocky-baseos
baseurl=${ROCKY_MIRROR}/${ROCKY_RELEASE}/BaseOS/${ARCH}/os/
enabled=1
gpgcheck=0

[rocky-appstream]
name=rocky-appstream
baseurl=${ROCKY_MIRROR}/${ROCKY_RELEASE}/AppStream/${ARCH}/os/
enabled=1
gpgcheck=0

[rocky-crb]
name=rocky-crb
baseurl=${ROCKY_MIRROR}/${ROCKY_RELEASE}/CRB/${ARCH}/os/
enabled=1
gpgcheck=0
EOF

SSH_CONFIG_DROPIN="${TMPDIR_CREATED}/99-debug-root.conf"
cat > "${SSH_CONFIG_DROPIN}" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
EOF

NM_KEYFILE="${TMPDIR_CREATED}/debug-dhcp.nmconnection"
cat > "${NM_KEYFILE}" <<'EOF'
[connection]
id=debug-dhcp
type=ethernet
autoconnect=true

[ipv4]
method=auto

[ipv6]
method=ignore
EOF

BASE_PACKAGES=(
    @Core
    acl
    attr
    NetworkManager
    audit
    bash-completion
    bind-utils
    chrony
    cryptsetup
    curl
    dnf
    dnf-plugins-core
    dosfstools
    dracut
    e2fsprogs
    ethtool
    file
    firewalld
    gdisk
    hostname
    iproute
    iputils
    irqbalance
    jq
    kmod
    less
    lsof
    libselinux-utils
    lvm2
    man-db
    man-pages
    mdadm
    net-tools
    nmap-ncat
    openssh-clients
    openssh-server
    pciutils
    parted
    policycoreutils
    policycoreutils-python-utils
    procps-ng
    psmisc
    qemu-guest-agent
    rsync
    rsyslog
    selinux-policy-targeted
    setools-console
    socat
    sudo
    tar
    tcpdump
    tmux
    tuned
    unzip
    usbutils
    util-linux
    util-linux-user
    vim-enhanced
    wget
    which
    xfsprogs
    xz
    zip
    zstd
)

DEBUG_PACKAGES=(
    bc
    blktrace
    bpftool
    bpftrace
    crash
    elfutils
    gdb
    gdb-gdbserver
    git
    iotop
    kernel-tools
    kernel-tools-libs
    kexec-tools
    lm_sensors
    ltrace
    numactl
    perf
    python3
    strace
    systemtap
    trace-cmd
)

TEST_PACKAGES=(
    fio
    iperf3
    stress-ng
    sysstat
)

BUILD_PACKAGES=(
    bison
    cmake
    elfutils-libelf-devel
    flex
    gcc
    gcc-c++
    glibc-devel
    libstdc++-devel
    make
    openssl-devel
    patch
    perl
    pkgconf-pkg-config
    python3-pip
    rpm-build
)

EXTRA_PACKAGES_ARR=()
if [[ -n "${EXTRA_PACKAGES}" ]]; then
    read -r -a EXTRA_PACKAGES_ARR <<< "${EXTRA_PACKAGES}"
fi

merge_packages \
    "${BASE_PACKAGES[@]}" \
    "${DEBUG_PACKAGES[@]}" \
    "${TEST_PACKAGES[@]}" \
    "${BUILD_PACKAGES[@]}" \
    "${EXTRA_PACKAGES_ARR[@]}"

DNF_INSTALL_OPTS=(
    --noplugins
    --setopt=module_platform_id="platform:el${ROCKY_RELEASE}"
    --setopt=install_weak_deps=False
)

if [[ "${INSTALL_DOCS}" == "0" ]]; then
    DNF_INSTALL_OPTS+=(--setopt=tsflags=nodocs)
fi

echo "Creating raw image: ${RAW_IMAGE} (${IMAGE_SIZE})"
rm -f "${RAW_IMAGE}" "${OUTPUT_IMAGE}"
qemu-img create -f raw "${RAW_IMAGE}" "${IMAGE_SIZE}" >/dev/null
mkfs.ext4 -F -L rootfs -m 0 "${RAW_IMAGE}" >/dev/null

sudo mkdir -p "${MOUNT_POINT}"
sudo mount -o loop "${RAW_IMAGE}" "${MOUNT_POINT}"

echo "Installing Rocky ${ROCKY_RELEASE} userspace into ${RAW_IMAGE}..."
sudo dnf -y \
    --installroot="${MOUNT_POINT}" \
    --releasever="${ROCKY_RELEASE}" \
    "${DNF_INSTALL_OPTS[@]}" \
    --setopt=reposdir="${REPO_DIR}" \
    --disablerepo='*' \
    --enablerepo=rocky-baseos \
    --enablerepo=rocky-appstream \
    --enablerepo=rocky-crb \
    install "${PACKAGES[@]}"

echo "Configuring guest image..."
echo "${VM_HOSTNAME}" | sudo tee "${MOUNT_POINT}/etc/hostname" >/dev/null
cat <<EOF | sudo tee "${MOUNT_POINT}/etc/hosts" >/dev/null
127.0.0.1   localhost localhost.localdomain
::1         localhost localhost.localdomain
127.0.1.1   ${VM_HOSTNAME}
EOF
sudo mkdir -p "${MOUNT_POINT}${GUEST_SHARE_MOUNT}"
cat <<'EOF' | sudo tee "${MOUNT_POINT}/etc/fstab" >/dev/null
/dev/vda  /  ext4  defaults  0 1
EOF
cat <<EOF | sudo tee -a "${MOUNT_POINT}/etc/fstab" >/dev/null
${SHARE_TAG}  ${GUEST_SHARE_MOUNT}  9p  trans=virtio,version=9p2000.L,_netdev,nofail,x-systemd.automount  0  0
EOF
sudo mkdir -p "${MOUNT_POINT}/etc/ssh/sshd_config.d"
sudo install -m 0644 "${SSH_CONFIG_DROPIN}" \
    "${MOUNT_POINT}/etc/ssh/sshd_config.d/99-debug-root.conf"

sudo mkdir -p "${MOUNT_POINT}/etc/NetworkManager/system-connections"
sudo install -m 0600 "${NM_KEYFILE}" \
    "${MOUNT_POINT}/etc/NetworkManager/system-connections/debug-dhcp.nmconnection"

if [[ -f "${SSH_PUBKEY}" ]]; then
    echo "Injecting SSH key from ${SSH_PUBKEY}"
    sudo install -d -m 0700 "${MOUNT_POINT}/root/.ssh"
    sudo install -m 0600 "${SSH_PUBKEY}" "${MOUNT_POINT}/root/.ssh/authorized_keys"
fi

echo "ttyS0" | sudo tee -a "${MOUNT_POINT}/etc/securetty" >/dev/null
sudo sed -ri "s/^SELINUX=.*/SELINUX=${SELINUX_MODE}/" "${MOUNT_POINT}/etc/selinux/config"
sudo sed -ri 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' "${MOUNT_POINT}/etc/selinux/config"

if [[ "${ENABLE_AUTORELABEL}" == "1" && "${SELINUX_MODE}" != "disabled" ]]; then
    sudo touch "${MOUNT_POINT}/.autorelabel"
fi
sudo truncate -s 0 "${MOUNT_POINT}/etc/machine-id"

sudo chroot "${MOUNT_POINT}" /bin/bash -c "ssh-keygen -A"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "echo 'root:${ROOT_PASSWORD}' | chpasswd"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "systemctl enable sshd.service"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "systemctl enable NetworkManager.service"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "systemctl enable chronyd.service"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "systemctl enable irqbalance.service"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "systemctl enable rsyslog.service"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "systemctl enable serial-getty@ttyS0.service"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "systemctl set-default multi-user.target"
sudo chroot "${MOUNT_POINT}" /bin/bash -c "dnf clean all"

sudo rm -rf "${MOUNT_POINT}/var/cache/dnf" "${MOUNT_POINT}/var/log/dnf"* \
    "${MOUNT_POINT}/var/log/hawkey.log"

sync
sudo umount "${MOUNT_POINT}"

echo "Converting raw image to qcow2: ${OUTPUT_IMAGE}"
qemu-img convert -f raw -O qcow2 "${RAW_IMAGE}" "${OUTPUT_IMAGE}"
qemu-img info "${OUTPUT_IMAGE}"

cat <<EOF

Build complete.

Raw image:
  ${RAW_IMAGE}

QCOW2 image:
  ${OUTPUT_IMAGE}

Use it with:
  ROOTFS_IMG=${OUTPUT_IMAGE} ${SCRIPT_DIR}/run_qemu_anolis.sh

Notes:
  - Installed package count: ${#PACKAGES[@]}
  - SELinux mode: ${SELINUX_MODE}
  - First-boot autorelabel: ${ENABLE_AUTORELABEL}
  - Package docs installed: ${INSTALL_DOCS}
  - Default root password: ${ROOT_PASSWORD}
  - Host SSH key injected: $( [[ -f "${SSH_PUBKEY}" ]] && echo yes || echo no )
  - Host share will automount at ${GUEST_SHARE_MOUNT} when ${SHARE_TAG} is exposed by run_qemu_anolis.sh
EOF
