#!/bin/bash
# GRUB core 模块二分（修正版：ceil 写入完整 core；cfg padding 用 true 命令）
ST=$HOME/hyos-build-grub/grub-2.12
BASE="biosdisk part_msdos fat configfile terminal serial halt echo"
source /mnt/vmiss/hyos-build/tests/embedboot.sh

mk() { local out=$1; shift; $ST/grub-mkimage -O i386-pc -o $out -d $ST/grub-core -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" "$@" && return 0; echo "MKIMG FAIL $out"; }

mk /tmp/b0.img $BASE
embed_and_boot /tmp/b0.img B0_MINIMAL
mk /tmp/b1.img $BASE normal linux reboot
embed_and_boot /tmp/b1.img B1_NLR
mk /tmp/b2.img $BASE net http pxe
embed_and_boot /tmp/b2.img B2_NET
mk /tmp/b3.img $BASE hyverify
embed_and_boot /tmp/b3.img B3_HYVERIFY
mk /tmp/b4.img $BASE normal linux reboot net http pxe hyverify
embed_and_boot /tmp/b4.img B4_FULL
