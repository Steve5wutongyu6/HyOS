#!/bin/bash
# 决定性实验：GRUB 自带 echo.c 作为新建模块 test 构建引导
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
OUT=/tmp/newmod
mkdir -p $OUT
source /mnt/vmiss/hyos-build/tests/embedboot.sh

SC="-std=gnu99 -fno-common -Os -m32 -march=i386 -mrtd -mregparm=3 -falign-functions=1 -falign-loops=1 -falign-jumps=1 -freg-struct-return -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow -Wa,-mx86-used-note=no -msoft-float -fno-omit-frame-pointer -fno-dwarf2-cfi-asm -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-PIE -fno-pie -fno-stack-protector -ffreestanding"
CPP="-DHAVE_CONFIG_H -DGRUB_MACHINE_PCBIOS=1 -DGRUB_MACHINE=I386_PC -nostdinc -isystem /usr/lib/gcc-cross/i686-linux-gnu/14/include -I$ST/include -I$ST -I$ST/grub-core -I$ST/grub-core/lib/libgcrypt-grub/src -DGRUB_FILE=\"newecho.c\""

# grub 自带 echo.c 复制并保持原样（其 GRUB_MOD_INIT(echo) 需改名）
sed 's/GRUB_MOD_INIT (echo)/GRUB_MOD_INIT (test)/; s/GRUB_MOD_FINI (echo)/GRUB_MOD_FINI (test)/' \
  $ST/grub-core/commands/echo.c > $OUT/newecho.c

i686-linux-gnu-gcc $SC $CPP -c $OUT/newecho.c -o $OUT/newecho.o || { echo CC_FAIL; exit 1; }
i686-linux-gnu-gcc -std=gnu99 -fno-common -Os -m32 -march=i386 -mregparm=3 -nostdlib -Wl,-melf_i386 -no-pie -Wl,-N -Wl,-r -Wl,--build-id=none -o $OUT/test.mod $OUT/newecho.o && echo LD_OK
cp $OUT/test.mod $ST/grub-core/test.mod
$ST/grub-mkimage -O i386-pc -o $OUT/core.img -d $ST/grub-core -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test && echo MKIMG_OK
embed_and_boot $OUT/core.img NEWMOD_GRUB_ECHO
