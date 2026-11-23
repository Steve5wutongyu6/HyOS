#!/bin/bash
# 按 Makefile 规则精确重建 syminfo.lst + moddep.lst（含 sort）
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
GC=$ST/grub-core
cd $GC

cat kernel_syms.lst extra_deps.lst > syminfo.lst.new
for m in *.module; do
  sh gensyminfo.sh "$m" >> syminfo.lst.new || exit 1
done
wc -l syminfo.lst.new

cat syminfo.lst.new | sort | gawk -f genmoddep.awk > moddep.lst
echo "MODDEP lines: $(wc -l < moddep.lst)"
grep -E "^(hyverify|disk|echo|halt):" moddep.lst
