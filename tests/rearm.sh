#!/bin/bash
# 设备 re-arm：清空服务端 epoch 状态、状态回 provisioned（联调常用）
set -euo pipefail
FX=${FX:-/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json}
URL=${URL:-http://127.0.0.1:8787}
FF=/mnt/vmiss/hyos-build/scripts/fixture-field.mjs
DID=$(node "$FF" "$FX" did)
OWNER=$(node "$FF" "$FX" owner_token)
curl -s -X POST "$URL/v1/rearm" \
  -H "authorization: Bearer $OWNER" \
  -H "content-type: application/json" \
  --data-raw "{\"did\":\"$DID\"}"
echo