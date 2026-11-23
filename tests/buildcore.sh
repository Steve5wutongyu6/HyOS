#!/bin/bash
# 从已集成的 GRUB 构建树产出带 hyverify 的 core.img（依赖闭包由 moddep.lst 自动处理）
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
OUT=/mnt/vmiss/hyos-build/build/core
mkdir -p $OUT
$ST/grub-mkimage -O i386-pc -o $OUT/core.img \
  -d $ST/grub-core -c /mnt/vmiss/hyos-build/grub/embed.cfg -p "(hd0,msdos1)/boot/grub" \
  biosdisk part_msdos fat linux normal configfile boot halt reboot serial terminal echo net http pxe disk hyverify \
  && echo CORE_OK && ls -la $OUT/core.img
