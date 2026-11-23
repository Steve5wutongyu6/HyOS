#!/bin/bash
# 四个对象逐一定位
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
MODDIR=/mnt/vmiss/hyos-build/grub
OUT=/tmp/modtest
source /mnt/vmiss/hyos-build/tests/embedboot.sh

CFLAGS="-m32 -Os -g0 -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -fno-pie -fno-PIE -ffreestanding -fno-builtin -fno-common -nostdinc -Wall -Wno-unused-function -Wno-unused-variable"
INC="-I$ST/include -I$ST -I$MODDIR -I$MODDIR/shim"
DEFS="-DGRUB_MACHINE_PCBIOS=1 -DGRUB_TARGET_CPU_I386=1 -DAES256=1 -DGRUB_FILE=\"mod.c\""

one() {
  local name=$1 obj=$2
  mkdir -p $OUT/$name
  i686-linux-gnu-gcc $CFLAGS $INC $DEFS -c $MODDIR/mod_empty.c -o $OUT/$name/empty.o 2>/dev/null
  i686-linux-gnu-gcc $CFLAGS $INC $DEFS -c $MODDIR/$obj -o $OUT/$name/obj.o 2>&1 | grep -E "error" | head -2
  i686-linux-gnu-ld -m elf_i386 -r -o $OUT/$name/test.mod $OUT/$name/empty.o $OUT/$name/obj.o || { echo "$name LD FAIL"; return; }
  i686-linux-gnu-objcopy -R .comment -R .note.gnu.property $OUT/$name/test.mod 2>/dev/null || true
  cp $OUT/$name/test.mod $ST/grub-core/test.mod
  $ST/grub-mkimage -O i386-pc -o $OUT/$name/core.img -d $ST/grub-core -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test || { echo "$name MKIMG FAIL"; return; }
  embed_and_boot $OUT/$name/core.img $name
}

one W_AES aes.c
one W_TWEETNACL tweetnacl.c
one W_HYSHA hysha.c
one W_HYGCM hygcm.c
