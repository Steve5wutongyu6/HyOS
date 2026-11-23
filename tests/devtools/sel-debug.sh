#!/bin/bash
# 重建用户态/initrd/镜像并引导（捕获 SELinux 加载错误）
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12
cd $REPO
bash scripts/build-userland.sh > /tmp/ul-dbg.log 2>&1 || { grep -E "^error" -A4 /tmp/ul-dbg.log | head -10; exit 1; }
bash scripts/build-initrd.sh > /tmp/ir-dbg.log 2>&1 || { tail -5 /tmp/ir-dbg.log; exit 1; }
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg > /dev/null 2>&1 || exit 1
bash $REPO/tests/rearm.sh > /dev/null 2>&1
rm -f /tmp/sel-e5.log
timeout 700 qemu-system-x86_64 -machine pc -m 1024 -display none -serial file:/tmp/sel-e5.log -drive file=$B/deploy-test.img,format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null
echo "Q_EXIT=$?"
grep -aE "SELINUX|PROBE|HYOS|HYVERIFY|SYS_OK|APP_OK|DESTROY|audit|avc" /tmp/sel-e5.log | head -30