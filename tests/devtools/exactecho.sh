#!/bin/bash
# 逐字节复刻 stock echo 编译命令（含 -g 与全部 flag），验证 debug 节假设
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
GC=$ST/grub-core
OUT=/tmp/exact
mkdir -p $OUT
source /mnt/vmiss/hyos-build/tests/embedboot.sh

sed 's/GRUB_MOD_INIT (echo)/GRUB_MOD_INIT (test)/; s/GRUB_MOD_FINI (echo)/GRUB_MOD_FINI (test)/' \
  $GC/commands/echo.c > $OUT/echo.c

cd $GC
i686-linux-gnu-gcc -DHAVE_CONFIG_H -I. -I..  -Wall -W  -DGRUB_MACHINE_PCBIOS=1 -DGRUB_MACHINE=I386_PC -m32 -nostdinc -isystem /usr/lib/gcc-cross/i686-linux-gnu/14/include -I../include -I../include -DGRUB_FILE=\"newecho.c\" -I. -I. -I.. -I.. -I../include -I../include -I../grub-core/lib/libgcrypt-grub/src/    -D_FILE_OFFSET_BITS=64 -std=gnu99 -fno-common -Os -m32 -Wall -W -Wshadow -Wpointer-arith -Wundef -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wfloat-equal -Wformat-extra-args -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmultichar -Wparentheses -Wreturn-type -Wsequence-point -Wshadow -Wsign-compare -Wswitch -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value  -Wunused-variable -Wwrite-strings -Wnested-externs -Wstrict-prototypes -g -Wredundant-decls -Wmissing-prototypes -Wmissing-declarations  -Wextra -Wattributes -Wendif-labels -Winit-self -Wint-to-pointer-cast -Winvalid-pch -Wmissing-field-initializers -Wnonnull -Woverflow -Wvla -Wpointer-to-int-cast -Wstrict-aliasing -Wvariadic-macros -Wvolatile-register-var -Wpointer-sign -Wmissing-include-dirs -Wmissing-prototypes -Wmissing-declarations -Wformat=2 -march=i386 -mrtd -mregparm=3 -falign-functions=1 -falign-loops=1 -falign-jumps=1 -freg-struct-return -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow -Wa,-mx86-used-note=no -msoft-float -fno-omit-frame-pointer -fno-dwarf2-cfi-asm -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-PIE -fno-pie -fno-stack-protector -Wtrampolines   -DGRUB_HAS_PCI -ffreestanding   -c -o $OUT/echo.o $OUT/echo.c && echo CC_OK

i686-linux-gnu-gcc -std=gnu99 -fno-common -Os -m32 -Wl,-melf_i386 -no-pie -Wl,--build-id=none  -nostdlib -Wl,-N -Wl,-r   -o $OUT/test.module $OUT/echo.o && echo LINK_OK
cp $OUT/test.module $GC/test.mod

$ST/grub-mkimage -O i386-pc -o $OUT/core.img -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test && echo MKIMG_OK
embed_and_boot $OUT/core.img EXACT_STOCK_ECHO
