#!/bin/bash
# 重组 deploy-test.img 后交互诊断:cfg 失败后在 rescue shell 里 dump 环境
set -o pipefail
cd /mnt/vmiss/hyos-build
B=/mnt/vmiss/hyos-build/build; GT=$HOME/hyos-build-grub/grub-2.12; K=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GT --work $B/work3 --out $B/deploy-test.img --cfg /mnt/vmiss/hyos-build/tests/grub-test.cfg > /tmp/mk3.log 2>&1 && echo ASSEMBLE_OK || { tail -6 /tmp/mk3.log; exit 1; }
(sleep 22; printf "set\r\n"; sleep 4; printf "lsmod\r\n"; sleep 6; printf "halt\r\n") | \
timeout 55 qemu-system-x86_64 -machine pc -m 1024 -display none -serial stdio \
  -drive file=$B/deploy-test.img,format=raw,if=ide \
  -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null | tail -70
