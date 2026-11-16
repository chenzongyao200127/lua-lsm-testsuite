#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build a minimal Debian rootfs for CI functional tests.
#
# Unlike create_rocky_selinux_rootfs.sh (dnf + SELinux + 48G, for local
# perf/debug work), this produces a small raw ext4 image with just what
# the functional workload needs: sshd with key auth, bash/awk/grep,
# dmesg/journalctl, DHCP networking, and the 9p host share at /mnt/host.
# All required kernel drivers must be built into the kernel under test
# (virtio-blk/net, 9p, ext4, 8250 console); no modules are installed.
#
# Environment variables:
#   OUTPUT        Output raw image path (default: ./rootfs-ci.img)
#   IMAGE_SIZE    Sparse image size (default: 2G)
#   SSH_PUBKEY    Path to the public key injected for root (required)
#   SUITE         Debian suite (default: bookworm)
#   MIRROR        Debian mirror (default: http://deb.debian.org/debian)
#
# Requires root: debootstrap, mkfs.ext4, loop mounts.

set -euo pipefail

OUTPUT="${OUTPUT:-$PWD/rootfs-ci.img}"
IMAGE_SIZE="${IMAGE_SIZE:-2G}"
SSH_PUBKEY="${SSH_PUBKEY:-}"
SUITE="${SUITE:-bookworm}"
MIRROR="${MIRROR:-http://deb.debian.org/debian}"

if [[ -z "$SSH_PUBKEY" || ! -r "$SSH_PUBKEY" ]]; then
    echo "SSH_PUBKEY must point to a readable public key file" >&2
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    echo "must run as root (loop mount + debootstrap)" >&2
    exit 1
fi
for cmd in debootstrap mkfs.ext4 mount umount truncate; do
    command -v "$cmd" >/dev/null || { echo "missing command: $cmd" >&2; exit 1; }
done

MNT="$(mktemp -d /tmp/ci-rootfs.XXXXXX)"
cleanup() {
    mountpoint -q "$MNT" && umount "$MNT"
    rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

truncate -s "$IMAGE_SIZE" "$OUTPUT"
mkfs.ext4 -q -F "$OUTPUT"
mount -o loop "$OUTPUT" "$MNT"

debootstrap --variant=minbase \
    --include=openssh-server,systemd,systemd-sysv,util-linux,bash,grep,mawk,coreutils,iproute2 \
    "$SUITE" "$MNT" "$MIRROR"

echo "lua-ci" > "$MNT/etc/hostname"

cat > "$MNT/etc/fstab" <<'EOF'
/dev/vda	/	ext4	defaults	0 1
host_share	/mnt/host	9p	trans=virtio,version=9p2000.L,rw,nofail	0 0
EOF
mkdir -p "$MNT/mnt/host"

mkdir -p "$MNT/root/.ssh"
cp "$SSH_PUBKEY" "$MNT/root/.ssh/authorized_keys"
chmod 700 "$MNT/root/.ssh"
chmod 600 "$MNT/root/.ssh/authorized_keys"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$MNT/etc/ssh/sshd_config"
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' "$MNT/etc/ssh/sshd_config"
chroot "$MNT" passwd -l root

mkdir -p "$MNT/etc/systemd/network"
cat > "$MNT/etc/systemd/network/20-dhcp.network" <<'EOF'
[Match]
Name=en* eth*

[Network]
DHCP=yes
EOF

chroot "$MNT" systemctl enable ssh.service systemd-networkd.service >/dev/null 2>&1

# Trim the image: apt caches and docs are dead weight in CI.
rm -rf "$MNT/var/cache/apt/archives/"*.deb "$MNT/var/lib/apt/lists/"* \
       "$MNT/usr/share/doc/"* "$MNT/usr/share/man/"*

umount "$MNT"
trap - EXIT
rmdir "$MNT"

echo "rootfs ready: $OUTPUT"