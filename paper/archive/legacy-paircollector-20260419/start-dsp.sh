#!/usr/bin/env bash
set -euo pipefail

qemu-system-x86_64 \
  -m 16384 \
  -smp 8 \
  -chardev socket,id=SOCKSYZ,server=on,wait=off,host=localhost,port=9307 \
  -mon chardev=SOCKSYZ,mode=control \
  -display none \
  -serial stdio \
  -no-reboot \
  -name VM-0 \
  -device virtio-rng-pci \
  -cpu host,migratable=off \
  -enable-kvm \
  -hdb "/home/zzzccc/BASS/DDRD-syzkaller/test/fs/btrfs-2G.qcow2" \
  -audiodev none,id=pa1 \
  -device AC97,audiodev=pa1 \
  -device e1000,netdev=net0 \
  -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:24652-:22 \
  -hda "/home/zzzccc/BASS/DDRD-syzkaller/test/fs/bookworm.img" \
  -snapshot \
  -kernel "/home/zzzccc/Linux-Kernel/DDRD-Kernel/arch/x86/boot/bzImage-intel-hda" \
  -append "root=/dev/sda console=ttyS0 net.ifnames=0"
