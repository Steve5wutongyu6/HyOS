#!/bin/bash
# 对象级二分 v2（stock flags + ceil 嵌入）
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
MODDIR=/mnt/vmiss/hyos-build/grub
OUT=/tmp/objtest
mkdir -p $OUT
source /mnt/vmiss/hyos-build/tests/embedboot.sh

cat > $OUT/mod_empty.c <<'EOF'
#include <grub/dl.h>
GRUB_MOD_LICENSE ("GPLv3+");
GRUB_MOD_INIT (test) { }
GRUB_MOD_FINI (test) { }
EOF

SC="-std=gnu99 -fno-common -Os -m32 -march=i386 -mrtd -mregparm=3 -falign-functions=1 -falign-loops=1 -falign-jumps=1 -freg-struct-return -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow -Wa,-mx86-used-note=no -msoft-float -fno-omit-frame-pointer -fno-dwarf2-cfi-asm -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-PIE -fno-pie -fno-stack-protector -ffreestanding"
CPP="-DHAVE_CONFIG_H -DGRUB_MACHINE_PCBIOS=1 -DGRUB_MACHINE=I386_PC -nostdinc -isystem /usr/lib/gcc-cross/i686-linux-gnu/14/include -I$ST/include -I$ST -I$MODDIR -I$MODDIR/shim"
DEFS="-DAES256=1 -DGRUB_FILE=\"mod.c\""

one() {
  local name=$1 obj=$2
  mkdir -p $OUT/$name
  i686-linux-gnu-gcc $SC $CPP $DEFS -c $OUT/mod_empty.c -o $OUT/$name/empty.o || { echo "$name CC_EMPTY_FAIL"; return; }
  i686-linux-gnu-gcc $SC $CPP $DEFS -c $MODDIR/$obj -o $OUT/$name/obj.o || { echo "$name CC_FAIL"; return; }
  i686-linux-gnu-gcc -std=gnu99 -fno-common -Os -m32 -march=i386 -mregparm=3 -nostdlib -Wl,-melf_i386 -no-pie -Wl,-N -Wl,-r -Wl,--build-id=none -o $OUT/$name/test.mod $OUT/$name/empty.o $OUT/$name/obj.o || { echo "$name LD_FAIL"; return; }
  cp $OUT/$name/test.mod $ST/grub-core/test.mod
  $ST/grub-mkimage -O i386-pc -o $OUT/$name/core.img -d $ST/grub-core -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test || { echo "$name MKIMG_FAIL"; return; }
  embed_and_boot $OUT/$name/core.img $name
}

one OBJ_AES aes.c
one OBJ_TNACL tweetnacl.c
one OBJ_HYSHA hysha.c
one OBJ_HYGCM hygcm.c
