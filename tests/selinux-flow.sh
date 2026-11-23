#!/bin/bash
# SELinux 集成联调：策略 → 用户态 → initrd → 镜像 → 引导
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12
bash $REPO/tests/cleanup.sh > /dev/null 2>&1
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

echo "=== 1. 策略 ==="
bash $REPO/selinux/build-policy.sh 2>&1 | tail -2 || exit 1

echo "=== 2. 密钥 ==="
cd $REPO/server && node ../scripts/gen-dev-keys.mjs > /dev/null 2>&1 && node ../scripts/gen-hykeys.mjs > /dev/null 2>&1
npx wrangler d1 execute hyos --local --file schema.sql > /dev/null 2>&1
curl -sf http://127.0.0.1:8787/v1/health > /dev/null 2>&1 || { setsid nohup npx wrangler dev --local --port 8787 > /tmp/wrangler.log 2>&1 < /dev/null & for i in $(seq 1 40); do sleep 1; curl -sf http://127.0.0.1:8787/v1/health > /dev/null 2>&1 && break; done; }
sudo pkill -f "socat TCP4-LISTEN:80" 2>/dev/null
sudo setsid nohup socat TCP4-LISTEN:80,fork,reuseaddr TCP4:127.0.0.1:8787 > /dev/null 2>&1 &
sleep 1
KEY_SERVER=http://127.0.0.1:8787 node ../tests/contract.mjs 2>&1 | tail -1
bash $REPO/tests/dbgrearm.sh > /dev/null 2>&1

echo "=== 3. GRUB + 用户态 ==="
cd $REPO && bash grub/build-grub.sh > /tmp/gb-sel.log 2>&1 || { tail -8 /tmp/gb-sel.log; exit 1; }
bash scripts/build-userland.sh > /tmp/ul-sel.log 2>&1 || { grep -E "^error" -A4 /tmp/ul-sel.log | head -12; exit 1; }

echo "=== 4. manifest + initrd ==="
$B/mkdisk manifest --core $B/core/core.img --keys $K --out-dir $B/manifests > /dev/null 2>&1 || exit 1
bash scripts/build-initrd.sh > /tmp/ir-sel.log 2>&1 || { tail -5 /tmp/ir-sel.log; exit 1; }
ls -la $B/selinux/policy $B/initrd.img | tail -2

echo "=== 5. 镜像 ==="
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg > /tmp/mk-sel.log 2>&1 || { tail -5 /tmp/mk-sel.log; exit 1; }
bash $REPO/tests/dbgrearm.sh > /dev/null 2>&1

echo "=== 6. 引导 ==="
rm -f /tmp/sel-e1.log
timeout 700 qemu-system-x86_64 -machine pc -m 1024 -display none -serial file:/tmp/sel-e1.log -drive file=$B/deploy-test.img,format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null
echo "Q_EXIT=$?"
echo "=== SELinux 证据 ==="
grep -aE "SELINUX|PROBE|HYOS|HYVERIFY|SYS_OK|APP_OK|ADVANCE|E2E SUCCESS|DESTROY" /tmp/sel-e1.log | head -30