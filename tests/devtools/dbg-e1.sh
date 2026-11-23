#!/bin/bash
# 调试 E1：重建带 DBG 的 hyinit → 引导 → 抓槽解析诊断
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12
echo ===BUILD_USERLAND===
cd $REPO && bash scripts/build-userland.sh > /tmp/uld.log 2>&1 || { tail -8 /tmp/uld.log; exit 1; }
echo ===INITRD===
bash scripts/build-initrd.sh > /tmp/ird.log 2>&1 || { tail -5 /tmp/ird.log; exit 1; }
echo ===IMAGE===
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg > /tmp/mkd.log 2>&1 || { tail -5 /tmp/mkd.log; exit 1; }
echo ===SERVER===
cd $REPO/server
curl -sf http://127.0.0.1:8787/v1/health > /dev/null 2>&1 || {
  setsid nohup npx wrangler dev --local --port 8787 > /tmp/wrangler.log 2>&1 < /dev/null &
  for i in $(seq 1 40); do sleep 1; curl -sf http://127.0.0.1:8787/v1/health > /dev/null 2>&1 && break; done
}
sudo pkill -f "socat TCP4-LISTEN:80" 2>/dev/null
sudo setsid nohup socat TCP4-LISTEN:80,fork,reuseaddr TCP4:127.0.0.1:8787 > /dev/null 2>&1 &
sleep 1
echo ===CONTRACT===
KEY_SERVER=http://127.0.0.1:8787 node ../tests/contract.mjs 2>&1 | tail -2
echo ===REARM===
bash $REPO/tests/rearmdbg.sh 2>&1 | tail -1
echo ===BOOT===
rm -f /tmp/e1d.log
timeout 700 qemu-system-x86_64 -machine pc -m 1024 -display none -serial file:/tmp/e1d.log -drive file=$B/deploy-test.img,format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null
echo Q_EXIT=$?
grep -aE "HYOS|HYVERIFY|DBG|SYS_OK|APP_OK|ADVANCE|NET UP|E2E SUCCESS" /tmp/e1d.log | head -30