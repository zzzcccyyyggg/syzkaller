#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Mirrors the QEMU command line emitted by syz-manager for usb-driver.cfg
exec qemu-system-x86_64 \
    -m 8192 \
    -smp 2 \
    -chardev socket,id=SOCKSYZ,server=on,wait=off,host=localhost,port=10039 \
    -mon chardev=SOCKSYZ,mode=control \
    -display none \
    -serial stdio \
    -no-reboot \
    -name VM-0 \
    -device virtio-rng-pci \
    -enable-kvm \
    -drive if=none,id=my-usb-drive,file="$SCRIPT_DIR/usb.img",format=raw \
    -device qemu-xhci,id=xhci \
    -device usb-storage,bus=xhci.0,drive=my-usb-drive \
    -device e1000,netdev=net0 \
    -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:49681-:22 \
    -hda "$SCRIPT_DIR/../fs/bookworm-usb.img" \
    -kernel /home/zzzccc/Linux-Kernel/DDRD-Kernel/arch/x86/boot/bzImage-usb-driver \
    -append "root=/dev/sda console=ttyS0"
