#!/bin/bash
# 不压缩 core + 手工模块 → 引导验证（绕开 LZMA 路径）
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
GC=$ST/grub-core
source /mnt/vmiss/hyos-build/tests/embedboot.sh

if [ ! -f /tmp/exact/test.module ]; then echo "no exact test.module"; exit 1; fi
cp /tmp/exact/test.module $GC/test.mod

$ST/grub-mkimage -C none -O i386-pc -o /tmp/none-core.img -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test && echo MKIMG_NONE_OK
ls -la /tmp/none-core.img
embed_and_boot /tmp/none-core.img NONECOMP_WITH_TEST
