#!/usr/bin/env bash
# Copyright 2016 ccwf project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# create-image.sh creates a minimal Debian Linux image suitable for ccwf.

set -eux

# Create a minimal Debian distribution in a directory.
PREINSTALL_PKGS=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros,debian-ports-archive-keyring,cmake,make,g++,iozone3,openssl,fio,mtd-utils,util-linux

# If ADD_PACKAGE is not defined as an external environment variable, use our default packages
if [ -z ${ADD_PACKAGE+x} ]; then
    ADD_PACKAGE="make,sysbench,git,vim,tmux,usbutils,tcpdump"
fi

ARCH=$(uname -m)
RELEASE=bookworm
FEATURE=minimal
SEEK=20479
PERF=false
OUTPUT_DIR=$PWD/output

# Display help function
display_help() {
    echo "Usage: $0 [option...] " >&2
    echo
    echo "   -a, --arch                 Set architecture"
    echo "   -d, --distribution         Set Debian distribution (e.g., bookworm)"
    echo "   -f, --feature              Choose installed packages: minimal, full"
    echo "   -s, --seek                 Image size in MB (default 20480)"
    echo "   -p, --add-perf             Enable perf support (requires \$KERNEL env)"
    echo "   -o, --output-dir           Set output directory"
    echo "   -h, --help                 Display this help message"
    echo
}

while true; do
    if [ $# -eq 0 ]; then break; fi
    case "$1" in
        -h|--help)
            display_help; exit 0 ;;
        -a|--arch)
            ARCH=$2; shift 2 ;;
        -d|--distribution)
            RELEASE=$2; shift 2 ;;
        -f|--feature)
            FEATURE=$2; shift 2 ;;
        -s|--seek)
            SEEK=$(($2 - 1)); shift 2 ;;
        -p|--add-perf)
            PERF=true; shift 1 ;;
        -o|--output-dir)
            OUTPUT_DIR=$2; shift 2 ;;
        -*|--*)
            echo "Unknown option: $1" >&2; exit 1 ;;
        *) break ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

case "$ARCH" in
    ppc64le) DEBARCH=ppc64el ;;
    aarch64) DEBARCH=arm64 ;;
    arm)     DEBARCH=armel ;;
    x86_64)  DEBARCH=amd64 ;;
    *)       DEBARCH=$ARCH ;;
esac

FOREIGN=false
if [ $ARCH != $(uname -m) ]; then
    if [ $ARCH != "i386" -o $(uname -m) != "x86_64" ]; then
        FOREIGN=true
    fi
fi

if [ $FOREIGN = true ]; then
    if ! which qemu-$ARCH-static; then
        echo "Install qemu static binary for $ARCH"; exit 1
    fi
    if [ ! -r /proc/sys/fs/binfmt_misc/qemu-$ARCH ]; then
        echo "Missing binfmt entry for qemu-$ARCH"; exit 1
    fi
fi

if [ $PERF = true ] && [ -z ${KERNEL+x} ]; then
    echo "KERNEL env var required when enabling perf"; exit 1
fi

if [ $FEATURE = "full" ]; then
    PREINSTALL_PKGS=$PREINSTALL_PKGS","$ADD_PACKAGE
fi

DIR=$OUTPUT_DIR/$RELEASE
sudo rm -rf $DIR
sudo mkdir -p $DIR
sudo chmod 0755 $DIR

DEBOOTSTRAP_PARAMS="--arch=$DEBARCH --include=$PREINSTALL_PKGS --components=main,contrib,non-free,non-free-firmware $RELEASE $DIR http://mirrors.tuna.tsinghua.edu.cn/debian/"
if [ $FOREIGN = true ]; then
    DEBOOTSTRAP_PARAMS="--foreign $DEBOOTSTRAP_PARAMS"
fi
if [ $DEBARCH == "riscv64" ]; then
    DEBOOTSTRAP_PARAMS="--keyring /usr/share/keyrings/debian-ports-archive-keyring.gpg --exclude firmware-atheros $DEBOOTSTRAP_PARAMS http://mirrors.tuna.tsinghua.edu.cn/debian-ports/"
fi

RET=0
sudo debootstrap $DEBOOTSTRAP_PARAMS || RET=$?
if [ $RET != 0 ] && [ $DEBARCH != "riscv64" ]; then
    DEBOOTSTRAP_PARAMS="--keyring /usr/share/keyrings/debian-archive-removed-keys.gpg $DEBOOTSTRAP_PARAMS https://archive.debian.org/debian-archive/debian/"
    sudo debootstrap $DEBOOTSTRAP_PARAMS
fi

if [ $FOREIGN = true ]; then
    sudo cp $(which qemu-$ARCH-static) $DIR/$(which qemu-$ARCH-static)
    sudo chroot $DIR /bin/bash -c "/debootstrap/debootstrap --second-stage"
fi

sudo sed -i '/^root/ { s/:x:/::/ }' $DIR/etc/passwd

echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $DIR/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $DIR/etc/network/interfaces

cat <<EOF | sudo tee -a $DIR/etc/fstab
/dev/root / ext4 defaults 0 0
debugfs /sys/kernel/debug debugfs defaults 0 0
securityfs /sys/kernel/security securityfs defaults 0 0
configfs /sys/kernel/config/ configfs defaults 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0
EOF

echo -en "127.0.0.1\tlocalhost\n" | sudo tee $DIR/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $DIR/etc/resolv.conf
echo "ccwf" | sudo tee $DIR/etc/hostname

ssh-keygen -f $OUTPUT_DIR/$RELEASE.id_rsa -t rsa -N ''
sudo mkdir -p $DIR/root/.ssh/
cat $OUTPUT_DIR/$RELEASE.id_rsa.pub | sudo tee $DIR/root/.ssh/authorized_keys

if [ $PERF = true ]; then
    cp -r $KERNEL $DIR/tmp/
    BASENAME=$(basename $KERNEL)
    sudo chroot $DIR /bin/bash -c "apt-get update; apt-get install -y flex bison python-dev libelf-dev libunwind8-dev libaudit-dev libslang2-dev libperl-dev binutils-dev liblzma-dev libnuma-dev"
    sudo chroot $DIR /bin/bash -c "cd /tmp/$BASENAME/tools/perf/; make"
    sudo chroot $DIR /bin/bash -c "cp /tmp/$BASENAME/tools/perf/perf /usr/bin/"
    rm -r $DIR/tmp/$BASENAME
fi

echo 'ATTR{name}=="vim2m", SYMLINK+="vim2m"' | sudo tee -a $DIR/etc/udev/rules.d/50-udev-default.rules

IMG=$OUTPUT_DIR/$RELEASE.img
dd if=/dev/zero of=$IMG bs=1M seek=$SEEK count=1
sudo mkfs.ext4 -F $IMG
sudo mkdir -p /mnt/$RELEASE
sudo mount -o loop $IMG /mnt/$RELEASE
sudo cp -a $DIR/. /mnt/$RELEASE/.
sudo umount /mnt/$RELEASE

qemu-img create -f raw $OUTPUT_DIR/disk.img 2G
mkfs.btrfs $OUTPUT_DIR/disk.img
qemu-img convert -O qcow2 $OUTPUT_DIR/disk.img $OUTPUT_DIR/disk.qcow2