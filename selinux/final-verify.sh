#!/bin/bash
# SELinux 最终验证（内核 6.14.11，策略 v34 原生）+ 部署密钥份额重组
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12

echo "=== 内核版本 ==="
strings $B/vmlinuz | grep -m1 "Linux version" | head -c 90; echo

echo "=== 1. 策略（v34 原生，无垫片）==="
bash $REPO/selinux/build-policy.sh 2>&1 | tail -3

echo "=== 2. 密钥 + 部署密钥嵌入 ==="
cd $REPO
if [ -f /tmp/gitkey_b64.txt ]; then export HYOS_GIT_SSH_KEY_B64=$(cat /tmp/gitkey_b64.txt); fi
node scripts/gen-dev-keys.mjs >/dev/null
node scripts/gen-hykeys.mjs >/dev/null
grep -c GIT_KEY verifier/src/genkeys.rs

echo "=== 3. 用户态 ==="
bash scripts/build-userland.sh > /tmp/ul-final.log 2>&1 || { grep -E "^error" -A4 /tmp/ul-final.log | head -12; exit 1; }
echo USERLAND_OK

echo "=== 4. GRUB + manifest + initrd + 镜像 ==="
bash grub/build-grub.sh > /tmp/gb-final.log 2>&1 || { tail -8 /tmp/gb-final.log; exit 1; }
$B/mkdisk manifest --core $B/core/core.img --keys $K --out-dir $B/manifests >/dev/null 2>&1 || exit 1
bash scripts/build-initrd.sh > /tmp/ir-final.log 2>&1 || { tail -5 /tmp/ir-final.log; exit 1; }
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg >/dev/null 2>&1 && echo IMAGE_OK || exit 1

echo "=== 5. 服务端 + rearm ==="
cd $REPO/server
curl -sf http://127.0.0.1:8787/v1/health >/dev/null 2>&1 || { setsid nohup npx wrangler dev --local --port 8787 > /tmp/wrangler.log 2>&1 < /dev/null & for i in $(seq 1 40); do sleep 1; curl -sf http://127.0.0.1:8787/v1/health >/dev/null 2>&1 && break; done; }
sudo pkill -f "socat TCP4-LISTEN:80" 2>/dev/null
sudo setsid nohup socat TCP4-LISTEN:80,fork,reuseaddr TCP4:127.0.0.1:8787 >/dev/null 2>&1 & sleep 1
KEY_SERVER=http://127.0.0.1:8787 node ../tests/contract.mjs 2>&1 | tail -1
bash $REPO/tests/rearm.sh 2>&1 | tail -1

echo "=== 6. 引导 ==="
rm -f /tmp/sel-final.log
timeout 700 qemu-system-x86_64 -machine pc -m 1024 -display none -serial file:/tmp/sel-final.log -drive file=$B/deploy-test.img,format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null
echo "Q_EXIT=$?"
echo "=== 证据 ==="
grep -aE "SELINUX|PROBE|GITKEY|HYOS|HYVERIFY|SYS_OK|APP_OK|ADVANCE|E2E SUCCESS|DESTROY|SPAWN_ERR|APP_FILE" /tmp/sel-final.log | head -40