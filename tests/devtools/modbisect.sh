#!/bin/bash
# hyverify 模块崩溃源二分 v2
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
MODDIR=/mnt/vmiss/hyos-build/grub
OUT=/tmp/modtest
mkdir -p $OUT
source /mnt/vmiss/hyos-build/tests/embedboot.sh

CFLAGS="-m32 -Os -g0 -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -fno-pie -fno-PIE -ffreestanding -fno-builtin -fno-common -nostdinc -Wall -Wno-unused-function -Wno-unused-variable"
INC="-I$ST/include -I$ST -I$MODDIR -I$MODDIR/shim"
DEFS="-DGRUB_MACHINE_PCBIOS=1 -DGRUB_TARGET_CPU_I386=1 -DAES256=1 -DGRUB_FILE=\"mod.c\""

# 变体源码
cat > $OUT/mod_empty.c <<'EOF'
#include <grub/dl.h>
GRUB_MOD_LICENSE ("GPLv3+");
GRUB_MOD_INIT (test) { }
GRUB_MOD_FINI (test) { }
EOF

# hyverify 源码改名为 test（与模块名一致），INIT 留空
sed 's/GRUB_MOD_INIT (hyverify)/GRUB_MOD_INIT (test)/; s/GRUB_MOD_FINI (hyverify)/GRUB_MOD_FINI (test)/' \
  $MODDIR/hyverify.c > $OUT/hyverify_test.c
# 去掉命令注册（INIT 体清空）
python3 - <<'PYEOF'
import re
p = "/tmp/modtest/hyverify_test.c"
s = open(p).read()
s = re.sub(r'GRUB_MOD_INIT \(test\)\s*\{[\s\S]*?\n\}', 'GRUB_MOD_INIT (test)\n{\n}', s, count=1)
open(p, "w").write(s)
print("empty-init variant:", "hyverify_boot" not in s.split("GRUB_MOD_INIT (test)")[1][:200])
PYEOF

build_variant() {
  local name=$1; shift
  mkdir -p $OUT/$name
  local objs=""
  for f in "$@"; do
    i686-linux-gnu-gcc $CFLAGS $INC $DEFS -c "$f" -o $OUT/$name/$(basename $f .c).o 2>&1 | grep -E "error" | head -3
    objs="$objs $OUT/$name/$(basename $f .c).o"
  done
  i686-linux-gnu-ld -m elf_i386 -r -o $OUT/$name/test.mod $objs || { echo "$name LD FAIL"; return 1; }
  # 剥离非代码节
  i686-linux-gnu-objcopy -R .comment -R .note.gnu.property $OUT/$name/test.mod 2>/dev/null || true
  cp $OUT/$name/test.mod $ST/grub-core/test.mod
  $ST/grub-mkimage -O i386-pc -o $OUT/$name/core.img -d $ST/grub-core -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test || { echo "$name MKIMG FAIL"; return 1; }
  embed_and_boot $OUT/$name/core.img $name
}

build_variant V1_DATA_ONLY $OUT/mod_empty.c $MODDIR/hysha.c $MODDIR/hygcm.c $MODDIR/aes.c $MODDIR/tweetnacl.c
build_variant V3_EMPTY_INIT $OUT/hyverify_test.c $MODDIR/hysha.c $MODDIR/hygcm.c $MODDIR/aes.c $MODDIR/tweetnacl.c
build_variant V4_FULL_TESTNAME $OUT/hyverify_test.c $MODDIR/hysha.c $MODDIR/hygcm.c $MODDIR/aes.c $MODDIR/tweetnacl.c
