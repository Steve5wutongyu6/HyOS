#!/bin/bash
# SELinux 端到端验证：策略 → initrd → 镜像 → rearm → 引导 → 证据
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12
echo "=== 策略 ==="
bash $REPO/selinux/build-policy.sh 2>&1 | tail -2
echo "=== initrd（含策略） ==="
bash $REPO/scripts/build-initrd.sh > /tmp/ir-v.log 2>&1 && echo INITRD_OK || { tail -5 /tmp/ir-v.log; exit 1; }
echo "=== 镜像 ==="
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg > /dev/null 2>&1 && echo IMAGE_OK || exit 1
echo "=== rearm ==="
bash $REPO/tests/rearm.sh 2>&1 | tail -1
echo "=== 引导 ==="
rm -f /tmp/sel-v.log
timeout 700 qemu-system-x86_64 -machine pc -m 1024 -display none -serial file:/tmp/sel-v.log -drive file=$B/deploy-test.img,format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null
echo "Q_EXIT=$?"
echo "=== 证据 ==="
grep -aE "SELINUX|PROBE|HYOS|HYVERIFY|SYS_OK|APP_OK|ADVANCE|E2E SUCCESS|DESTROY|avc|denied" /tmp/sel-v.log | head -40