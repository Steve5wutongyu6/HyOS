#!/bin/bash
# 通过串口 stdin 在 GRUB shell 里交互诊断
(sleep 25; printf "lsmod\r\n"; sleep 4; printf "hyverify_boot\r\n"; sleep 12; printf "halt\r\n") | \
timeout 60 qemu-system-x86_64 -machine pc -m 1024 -display none -serial stdio \
  -drive file=/mnt/vmiss/hyos-build/build/deploy-test.img,format=raw,if=ide \
  -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null | tail -60
