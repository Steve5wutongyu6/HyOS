#!/bin/bash
# 清理残留：wrangler/esbuild/workerd/qemu/socat（不含 e2e 自身，避免自杀）
pkill -9 -f "wrangler-dist/cli.js" 2>/dev/null
pkill -9 -f "[w]orkerd" 2>/dev/null
pkill -9 -f "[e]sbuild --service" 2>/dev/null
pkill -9 -f "[q]emu-system" 2>/dev/null
sudo pkill -9 -f "socat TCP4-LISTEN:80" 2>/dev/null
sleep 2
echo "workerd=$(pgrep -c workerd 2>/dev/null || echo 0) qemu=$(pgrep -c qemu-system 2>/dev/null || echo 0) node=$(pgrep -c node 2>/dev/null || echo 0)"