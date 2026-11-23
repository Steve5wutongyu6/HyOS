#!/bin/bash
# 尺寸阈值实验：pad embed.cfg 增大 core，测启动与否
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
source /mnt/vmiss/hyos-build/tests/embedboot.sh

make_cfg() {
  local out=$1 lines=$2 tag=$3
  python3 - "$out" "$lines" "$tag" <<'PYEOF'
import sys
out, lines, tag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
pad = "#" + " A"*60 + chr(10)
cfg = "serial --unit=0 --speed=115200" + chr(10)
cfg += "terminal_output --append serial" + chr(10)
cfg += pad * lines
cfg += "echo " + tag + chr(10) + "halt" + chr(10)
open(out, "w").write(cfg)
print("cfg bytes:", len(cfg))
PYEOF
}

run() {
  local cfgf=$1 out=$2 name=$3
  $ST/grub-mkimage -O i386-pc -o $out -d $ST/grub-core -c $cfgf -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo || return 1
  ls -la $out | awk '{print $5, $9}'
  embed_and_boot $out $name
}

make_cfg /tmp/pad0.cfg 0 PAD0
run /tmp/pad0.cfg /tmp/b0p.img SZ_0PAD
make_cfg /tmp/pad4.cfg 4 PAD240
run /tmp/pad4.cfg /tmp/b4p.img SZ_240B
make_cfg /tmp/pad200.cfg 200 PAD12K
run /tmp/pad200.cfg /tmp/b200p.img SZ_12K
