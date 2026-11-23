#!/bin/bash
# Lima 内：rust 补装（正确用户）+ wrangler 安装 + 本地 D1 初始化 + 契约测试
set -euxo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v rustc >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi
rustc --version
cd /mnt/vmiss/hyos-build/server
npm install --no-fund --no-audit 2>&1 | tail -2
node ../scripts/gen-dev-keys.mjs
npx wrangler d1 execute hyos --local --file schema.sql 2>&1 | tail -3
pkill -f "wrangler dev" 2>/dev/null || true
nohup npx wrangler dev --local --port 8787 > /tmp/wrangler.log 2>&1 &
for i in $(seq 1 60); do
  sleep 1
  curl -sf http://127.0.0.1:8787/v1/health >/dev/null 2>&1 && break
done
curl -sf http://127.0.0.1:8787/v1/health
echo ""
KEY_SERVER=http://127.0.0.1:8787 node ../tests/contract.mjs
echo CONTRACT_DONE
