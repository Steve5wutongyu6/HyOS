#!/bin/bash
# 用 GRUB 自身的完整编译 flag 构建 hyverify 模块并引导测试
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
MODDIR=/mnt/vmiss/hyos-build/grub
OUT=/tmp/stocktest
mkdir -p $OUT
source /mnt/vmiss/hyos-build/tests/embedboot.sh

STOCK_CFLAGS="-std=gnu99 -fno-common -Os -m32 -march=i386 -mrtd -mregparm=3 -falign-functions=1 -falign-loops=1 -falign-jumps=1 -freg-struct-return -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow -Wa,-mx86-used-note=no -msoft-float -fno-omit-frame-pointer -fno-dwarf2-cfi-asm -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-PIE -fno-pie -fno-stack-protector -ffreestanding"
CPP="-DHAVE_CONFIG_H -DGRUB_MACHINE_PCBIOS=1 -DGRUB_MACHINE=I386_PC -nostdinc -isystem /usr/lib/gcc-cross/i686-linux-gnu/14/include -I$ST/include -I$ST -I$MODDIR -I$MODDIR/shim"
DEFS="-DAES256=1"

sed 's/GRUB_MOD_INIT (hyverify)/GRUB_MOD_INIT (test)/; s/GRUB_MOD_FINI (hyverify)/GRUB_MOD_FINI (test)/' $MODDIR/hyverify.c > $OUT/hyverify_test.c

objs=""
i686-linux-gnu-gcc $STOCK_CFLAGS $CPP $DEFS -DGRUB_FILE=\"hyverify.c\" -c $OUT/hyverify_test.c -o $OUT/hyverify_test.o && objs="$objs $OUT/hyverify_test.o" || { echo "CC FAIL hyverify"; exit 1; }
i686-linux-gnu-gcc $STOCK_CFLAGS $CPP $DEFS -DGRUB_FILE=\"hysha.c\" -c $MODDIR/hysha.c -o $OUT/hysha.o && objs="$objs $OUT/hysha.o" || { echo "CC FAIL hysha"; exit 1; }
i686-linux-gnu-gcc $STOCK_CFLAGS $CPP $DEFS -DGRUB_FILE=\"hygcm.c\" -c $MODDIR/hygcm.c -o $OUT/hygcm.o && objs="$objs $OUT/hygcm.o" || { echo "CC FAIL hygcm"; exit 1; }
i686-linux-gnu-gcc $STOCK_CFLAGS $CPP $DEFS -DGRUB_FILE=\"aes.c\" -c $MODDIR/aes.c -o $OUT/aes.o && objs="$objs $OUT/aes.o" || { echo "CC FAIL aes"; exit 1; }
i686-linux-gnu-gcc $STOCK_CFLAGS $CPP $DEFS -DGRUB_FILE=\"tweetnacl.c\" -c $MODDIR/tweetnacl.c -o $OUT/tweetnacl.o && objs="$objs $OUT/tweetnacl.o" || { echo "CC FAIL tweetnacl"; exit 1; }

i686-linux-gnu-gcc -std=gnu99 -fno-common -Os -m32 -march=i386 -mregparm=3 -nostdlib -Wl,-melf_i386 -no-pie -Wl,-N -Wl,-r -o $OUT/test.mod $objs && echo LD_OK
cp $OUT/test.mod $ST/grub-core/test.mod
$ST/grub-mkimage -O i386-pc -o $OUT/core.img -d $ST/grub-core -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test && echo MKIMG_OK
embed_and_boot $OUT/core.img STOCKFLAGS_FULL
