#!/bin/bash
# T1: stock halt.module 作为 test（名字失配） / T2: stock echo.module 复制为 test（内容重复）
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
GC=$ST/grub-core
source /mnt/vmiss/hyos-build/tests/embedboot.sh

# T5: 树还健康吗
if make -C $ST/grub-core AWK=gawk echo.module > /tmp/t5.log 2>&1; then echo "T5_TREE_OK"; else echo "T5_TREE_BROKEN"; tail -3 /tmp/t5.log; fi

# T1: halt 作为 test（列表无 halt，有 test）
cp $GC/halt.module $GC/test.mod
$ST/grub-mkimage -C none -O i386-pc -o /tmp/t1.img -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial echo test
embed_and_boot /tmp/t1.img T1_HALTMOD_AS_TEST

# T2: echo.module 复制为 test.mod，列表同时含 echo+test
cp $GC/echo.module $GC/test.mod
$ST/grub-mkimage -C none -O i386-pc -o /tmp/t2.img -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test
embed_and_boot /tmp/t2.img T2_ECHO_DUPLICATE
