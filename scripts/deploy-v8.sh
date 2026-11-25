#!/bin/bash
# HyOS v8 部署法：活系统内分块 O_DIRECT dd + 逐块回读校验 + 全盘 O_DIRECT 复核 + reboot -f
# 用法: bash deploy-v8.sh <image.tgz> <目标盘 /dev/vda> <镜像sha256>
# 前置: Debian 活系统内运行; img 已解压; bs=4M 分块
set -euo pipefail
IMG="$1"; DEV="${2:-/dev/vda}"; WANT="${3:?need sha256}"
echo "[1/4] 本地镜像校验"
GOT=$(sha256sum "$IMG" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "SHA MISMATCH local"; exit 1; }
echo "[2/4] 分块 O_DIRECT 写入 + 逐块回读校验"
SIZE=$(stat -c%s "$IMG")
CHUNK=$((4*1024*1024))
N=$(( (SIZE + CHUNK - 1) / CHUNK ))
FAIL=0
for i in $(seq 0 $((N-1))); do
  SKIP=$((i*CHUNK)); LEN=$(( CHUNK < SIZE-SKIP ? CHUNK : SIZE-SKIP ))
  dd if="$IMG" of="$DEV" bs=$CHUNK skip=$i seek=$i count=1 oflag=direct conv=notrunc status=none
  A=$(dd if="$IMG" bs=$CHUNK skip=$i count=1 status=none | sha256sum | cut -d' ' -f1)
  B=$(dd if="$DEV" bs=$LEN skip=$SKIP count=1 iflag=direct status=none 2>/dev/null | sha256sum | cut -d' ' -f1)
  [ "$A" = "$B" ] || { echo "CHUNK $i MISMATCH retry"; dd if="$IMG" of="$DEV" bs=$CHUNK skip=$i seek=$i count=1 oflag=direct conv=notrunc status=none; \
    B=$(dd if="$DEV" bs=$LEN skip=$SKIP count=1 iflag=direct status=none 2>/dev/null | sha256sum | cut -d' ' -f1); \
    [ "$A" = "$B" ] || { echo "CHUNK $i FAIL2"; FAIL=1; }; }
  [ $((i % 4)) -eq 0 ] && echo "chunk $i/$N ok"
done
[ $FAIL -eq 0 ] || { echo "DEPLOY_ABORT chunk fails"; exit 1; }
echo "[3/4] 全盘 O_DIRECT 复核"
A=$(sha256sum < "$IMG" | cut -d' ' -f1)
B=$(dd if="$DEV" bs=4M count=$N iflag=direct status=none 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "$A" = "$B" ] || { echo "FULL_VERIFY_FAIL"; exit 1; }
echo "FULL_VERIFY_OK"
echo "[4/4] reboot -f（唯一安全的重启路径；面板强制重置会丢宿主缓存）"
sync
reboot -f
