#!/bin/bash
# HyOS 写盘（v8 教训）：分块 O_DIRECT 写 + 同尺寸 O_DIRECT 回读逐块校验 + 全盘复核 + reboot -f
set -euo pipefail
IMG="$1"; DEV="$2"; WANT="$3"
[ -n "$IMG" ] && [ -n "$WANT" ] || { echo "usage: deploy-v8.sh IMG DEV SHA"; exit 2; }
[ -n "$DEV" ] || DEV=/dev/vda
CHUNK=$((4*1024*1024))
SIZE=$(stat -c%s "$IMG")

echo "[1/4] 镜像校验"
GOT=$(sha256sum "$IMG" | cut -d" " -f1)
[ "$GOT" = "$WANT" ] || { echo "SHA_MISMATCH_LOCAL got=$GOT"; exit 1; }
echo "  OK $GOT size=$SIZE"

echo "[2/4] 分块 O_DIRECT 写 + 逐块回读"
N=$(( (SIZE + CHUNK - 1) / CHUNK ))
FAIL=0
for i in $(seq 0 $((N-1))); do
  OFF=$((i*CHUNK))
  LEN=$((SIZE-OFF))
  if [ $LEN -gt $CHUNK ]; then LEN=$CHUNK; fi
  dd if="$IMG" of="$DEV" bs=$CHUNK skip=$i seek=$i count=1 oflag=direct conv=notrunc status=none
  sync
  if [ $LEN -eq $CHUNK ]; then
    A=$(dd if="$IMG" bs=$CHUNK skip=$i count=1 status=none | sha256sum | cut -d" " -f1)
    B=$(dd if="$DEV" bs=$CHUNK skip=$i count=1 iflag=direct status=none 2>/dev/null | sha256sum | cut -d" " -f1)
  else
    BLK=$((LEN/512))
    A=$(dd if="$IMG" bs=512 skip=$((OFF/512)) count=$BLK status=none | sha256sum | cut -d" " -f1)
    B=$(dd if="$DEV" bs=512 skip=$((OFF/512)) count=$BLK iflag=direct status=none 2>/dev/null | sha256sum | cut -d" " -f1)
  fi
  if [ "$A" != "$B" ]; then
    echo "  chunk $i MISMATCH retry"
    dd if="$IMG" of="$DEV" bs=$CHUNK skip=$i seek=$i count=1 oflag=direct conv=notrunc status=none; sync
    if [ $LEN -eq $CHUNK ]; then
      B=$(dd if="$DEV" bs=$CHUNK skip=$i count=1 iflag=direct status=none 2>/dev/null | sha256sum | cut -d" " -f1)
    else
      B=$(dd if="$DEV" bs=512 skip=$((OFF/512)) count=$((LEN/512)) iflag=direct status=none 2>/dev/null | sha256sum | cut -d" " -f1)
    fi
    if [ "$A" != "$B" ]; then echo "  chunk $i FAIL2"; FAIL=1; fi
  fi
  echo "  chunk $i/$N ok len=$LEN"
done
[ $FAIL -eq 0 ] || { echo "DEPLOY_ABORT chunk_fail"; exit 1; }
echo "  CHUNKS_OK"

echo "[3/4] 全盘 O_DIRECT 复核"
A=$(sha256sum < "$IMG" | cut -d" " -f1)
B=$(dd if="$DEV" bs=4096 count=$((SIZE/4096)) iflag=direct status=none 2>/dev/null | sha256sum | cut -d" " -f1)
[ "$A" = "$B" ] || { echo "FULL_VERIFY_FAIL want=$A got=$B"; exit 1; }
echo "  FULL_VERIFY_OK $A"

echo "[4/4] sync + reboot -f（勿用面板强制重置）"
sync
reboot -f
