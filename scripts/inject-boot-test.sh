#!/bin/bash
# 注入路径本地验证：重启本地 worker（载入新 SRV_SK）→ QEMU 引导目标镜像 → 断言注入证据
set -uo pipefail
IMG=$1
if [ -z "$IMG" ] || [ ! -s "$IMG" ]; then echo "用法: $0 <镜像路径>"; exit 2; fi
echo "=== 重启本地 worker（载入最新 .dev.vars）==="
sudo pkill -f 'wrangler[ ]dev[ ]--local' 2>/dev/null
sleep 1
cd /mnt/vmiss/hyos-build/server
setsid nohup npx wrangler dev --local --port 8787 > /tmp/wrangler2.log 2>&1 < /dev/null &
for i in $(seq 1 30); do sleep 1; curl -sf http://127.0.0.1:8787/v1/health >/dev/null 2>&1 && break; done
curl -sf http://127.0.0.1:8787/v1/health && echo " worker UP"
echo "=== socat 80 -> 8787 ==="
sudo pkill -f 'socat[ ]TCP4-LISTEN:80' 2>/dev/null
sudo setsid nohup socat TCP4-LISTEN:80,fork,reuseaddr TCP4:127.0.0.1:8787 >/dev/null 2>&1 &
sleep 1
echo "=== QEMU 注入引导 ==="
rm -f /tmp/inject-boot.log
timeout 150 qemu-system-x86_64 -machine pc -m 1024 -display none -serial file:/tmp/inject-boot.log \
  -drive file="$IMG",format=raw,if=ide -netdev user,id=n0 \
  -device e1000,netdev=n0,romfile=/usr/share/qemu/pxe-e1000.rom -no-reboot 2>/dev/null
echo "Q_EXIT=$?"
echo "=== 注入证据 ==="
grep -aE "NET UP|NET GW|E2E SUCCESS|DESTROY|SPAWN|APP_OK|ADVANCE" /tmp/inject-boot.log | head -12
