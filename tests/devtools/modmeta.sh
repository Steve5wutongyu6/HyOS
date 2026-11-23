#!/bin/bash
# 给 grub-core 里手放的 test.mod 注入 syminfo/moddep 元数据，然后 mkimage + 引导验证
# 用法: modmeta.sh <mod-file-name-without-ext> <core-output> <label> [modules...]
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
GC=$ST/grub-core
source /mnt/vmiss/hyos-build/tests/embedboot.sh

NAME=$1; shift
COREOUT=$1; shift
LABEL=$1; shift
MODULES="$@"

# 1) 生成 syminfo 条目（与 gensyminfo.sh 完全同构）
i686-linux-gnu-nm -g --defined-only -P -p $GC/$NAME.mod | sed "s@^\([^ ]*\).*@defined $NAME \1@g" > /tmp/sym_$NAME.lst
i686-linux-gnu-nm -u -P -p $GC/$NAME.mod | sed "s@^\([^ ]*\).*@undefined $NAME \1@g" >> /tmp/sym_$NAME.lst
wc -l /tmp/sym_$NAME.lst

# 2) 并入 syminfo.lst（先去重旧行），重算 moddep.lst
grep -v "^\(defined\|undefined\) $NAME " $GC/syminfo.lst > $GC/syminfo.lst.new
cat /tmp/sym_$NAME.lst >> $GC/syminfo.lst.new
mv $GC/syminfo.lst.new $GC/syminfo.lst
cat $GC/syminfo.lst | sort | gawk -f $GC/genmoddep.awk > $GC/moddep.lst.new && mv $GC/moddep.lst.new $GC/moddep.lst
grep "^$NAME:" $GC/moddep.lst

# 3) mkimage + 引导
$ST/grub-mkimage -O i386-pc -o $COREOUT -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" $MODULES && echo MKIMG_OK
embed_and_boot $COREOUT $LABEL
