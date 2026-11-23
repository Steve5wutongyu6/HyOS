#!/bin/bash
# SELinux 验证：重建镜像（上一次销毁会擦除 p3）→ rearm → 引导 → 抓证据
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12
echo "=== 重组镜像 ==="
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello \
  --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg 2>&1 | tail -1
echo "=== rearm ==="
bash $REPO/tests/rearm.sh 2>&1 | tail -1
echo "=== 引导 ==="
rm -f /tmp/sel-e4.log
timeout 700 qemu-system-x86_64 -machine pc -m 1024 -display none -serial file:/tmp/sel-e4.log -drive file=$B/deploy-test.img,format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null
echo "Q_EXIT=$?"
echo "=== 证据 ==="
grep -aE "SELINUX|PROBE|HYOS|HYVERIFY|SYS_OK|APP_OK|ADVANCE|E2E SUCCESS|DESTROY" /tmp/sel-e4.log | head -32