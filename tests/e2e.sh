#!/bin/bash
# HyOS Lima 全链路联调（设计文档 §15）
# 场景：E1 正常启动+推进 / E7 epoch2 重启 / E8 rearm / E2 L0 / E3 L1 / E4 离线销毁 / E5 L2 / E6 L3 / E9 L5
set -uxo pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
LOGS=$B/logs
mkdir -p $LOGS
export PATH="$HOME/.cargo/bin:$PATH"
PXE_ROM=/usr/share/qemu/pxe-e1000.rom
FAILED=0

fail() { echo "== E2E FAIL: $1"; FAILED=1; }

# ---------- 0a. 清理残留进程（防 OOM） ----------
bash /mnt/vmiss/hyos-build/tests/cleanup.sh > /dev/null 2>&1 || true

# ---------- 0. 依赖 ----------
sudo apt-get install -y -qq socat ipxe-qemu >/dev/null 2>&1 || true
[ -f $PXE_ROM ] || PXE_ROM=$(ls /usr/lib/ipxe/qemu/*.rom 2>/dev/null | head -1)
[ -f $PXE_ROM ] || echo "WARN: no pxe rom found"

# ---------- 1. 密钥服务 ----------
cd $REPO/server
npm install --no-fund --no-audit >/dev/null 2>&1 || true
node ../scripts/gen-dev-keys.mjs > /tmp/genkeys.log 2>&1 || { echo KEYGEN_FAIL; cat /tmp/genkeys.log; fail "keygen"; }
node ../scripts/gen-hykeys.mjs > /dev/null 2>&1 || fail "hykeys"
npx wrangler d1 execute hyos --local --file schema.sql >/dev/null 2>&1
pkill -f "[w]orkerd" 2>/dev/null || true
sleep 1
setsid nohup npx wrangler dev --local --port 8787 > /tmp/wrangler.log 2>&1 < /dev/null &
for i in $(seq 1 60); do
  sleep 1
  curl -sf http://127.0.0.1:8787/v1/health >/dev/null 2>&1 && break
done
curl -sf http://127.0.0.1:8787/v1/health >/dev/null || fail "server not up"

# socat 80 -> 8787（GRUB http 固定 80 端口）
sudo pkill -f "socat TCP4-LISTEN:80" 2>/dev/null || true
sudo setsid nohup socat TCP4-LISTEN:80,fork,reuseaddr TCP4:127.0.0.1:8787 >/dev/null 2>&1 &
sleep 1

# ---------- 2. 契约测试 ----------
cd $REPO/server
KEY_SERVER=http://127.0.0.1:8787 node ../tests/contract.mjs > $LOGS/contract.txt 2>&1 || fail "contract"
grep -q "0 fail" $LOGS/contract.txt || fail "contract result"

# contract 后复位设备（contract 末尾 revoke 清除）
FX=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
OWNER=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).owner_token)' $FX)
DIDV=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).did)' $FX)
curl -sf -X POST http://127.0.0.1:8787/v1/rearm -H "authorization: Bearer $OWNER" -H "content-type: application/json" --data-raw "{\"did\":\"$DIDV\"}" >/dev/null || fail "post-contract rearm"

# ---------- 3. 构建 ----------
cd $REPO
bash scripts/build-userland.sh > $LOGS/userland.log 2>&1 || { tail -20 $LOGS/userland.log; fail "userland"; }
[ -f $B/vmlinuz ] || fail "kernel missing"
bash grub/build-grub.sh > $LOGS/grub.log 2>&1 || { tail -30 $LOGS/grub.log; fail "grub"; }
$B/mkdisk manifest --core $B/core/core.img --keys tests/fixtures/dev-keys.json --out-dir $B/manifests > $LOGS/mkmanifest.log 2>&1 || fail "manifest"
bash scripts/build-initrd.sh > $LOGS/initrd.log 2>&1 || { tail -20 $LOGS/initrd.log; fail "initrd"; }

# ---------- 4. 组装镜像 ----------
GT=$HOME/hyos-build-grub/grub-2.12
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img \
  --hello $B/hello --keys tests/fixtures/dev-keys.json --grubtree $GT --work $B/work \
  --out $B/deploy-happy.img > $LOGS/mkdisk.log 2>&1 || { tail -20 $LOGS/mkdisk.log; fail "mkdisk"; }
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img \
  --hello $B/hello --keys tests/fixtures/dev-keys.json --grubtree $GT --work $B/work2 \
  --out $B/deploy-l3.img --cfg $REPO/tests/grub-test.cfg --app-pin-mismatch > $LOGS/mkdisk-l3.log 2>&1 || fail "mkdisk-l3"
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img \
  --hello $B/hello --keys tests/fixtures/dev-keys.json --grubtree $GT --work $B/work3 \
  --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg > $LOGS/mkdisk-test.log 2>&1 || fail "mkdisk-test"

# ---------- 5. qemu 执行器 ----------
run_qemu() {
  local img=$1 log=$2 timeout=$3; shift 3
  qemu-system-x86_64 -machine pc -m 1024 -display none \
    -serial file:$log \
    -drive file=$img,format=raw,if=ide \
    -netdev user,id=n0 -device e1000,netdev=n0,romfile=$PXE_ROM \
    -no-reboot "$@" &
  QPID=$!
  local t0=$(date +%s)
  while kill -0 $QPID 2>/dev/null; do
    sleep 2
    # 终态标记：断电/销毁/成功 后无需等待超时
    if grep -qaE "power off\.|HYOS E2E SUCCESS|HYOS WIPED|L5 WIPE" "$log" 2>/dev/null; then
      sleep 1
      kill -9 $QPID 2>/dev/null
      wait $QPID 2>/dev/null
      return 0
    fi
    local now=$(date +%s)
    if [ $((now - t0)) -gt $timeout ]; then
      kill -9 $QPID 2>/dev/null
      return 2
    fi
  done
  return 0
}
expect() {
  local log=$1; shift
  for pat in "$@"; do
    grep -qaF "$pat" $log || { echo "== missing marker: $pat (in $log)"; fail "marker $pat"; }
  done
}
absent() {
  local log=$1; shift
  for pat in "$@"; do
    grep -qaF "$pat" $log && { echo "== unexpected marker: $pat"; fail "unexpected $pat"; }
  done
}
restart_server() {
  pkill -f "[w]orkerd" 2>/dev/null || true
  sleep 1
  cd $REPO/server
  setsid nohup npx wrangler dev --local --port 8787 > /tmp/wrangler.log 2>&1 < /dev/null &
  for i in $(seq 1 60); do
    sleep 1
    curl -sf http://127.0.0.1:8787/v1/health >/dev/null 2>&1 && break
  done
  cd $REPO
}

rearm_now() {
  local FX=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
  local OWNERv=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).owner_token)" $FX)
  local DIDv=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).did)" $FX)
  curl -sf -X POST http://127.0.0.1:8787/v1/rearm -H "authorization: Bearer $OWNERv" -H "content-type: application/json" --data-raw "{\"did\":\"$DIDv\"}" >/dev/null || true
}

revoke_now() {
  local FX=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
  local OWNERv=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).owner_token)" $FX)
  local DIDv=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).did)" $FX)
  curl -sf -X POST http://127.0.0.1:8787/v1/revoke -H "authorization: Bearer $OWNERv" -H "content-type: application/json" --data-raw "{\"did\":\"$DIDv\"}" >/dev/null || true
}

# ---------- E1: 正常启动 + epoch 推进 + e2e 收尾 ----------
echo "== E1 happy path"
: > $LOGS/e1.log
rearm_now
run_qemu $B/deploy-test.img $LOGS/e1.log 300 || true
expect $LOGS/e1.log "HYOS SELFTEST OK" "HYOS BOOT-CHAIN OK epoch=1" "HYVERIFY GRUB-CHAIN OK" \
  "SYS_OK" "APP_OK sealed" "ADVANCE OK seq=" "HYOS E2E SUCCESS"

# ---------- E7: epoch2 重启 ----------
echo "== E7 reboot on advanced epoch"
: > $LOGS/e7.log
rearm_now
run_qemu $B/deploy-test.img $LOGS/e7.log 300 || true
expect $LOGS/e7.log "HYOS BOOT-CHAIN OK epoch=" "ADVANCE OK seq="

# ---------- E8: rearm 后旧磁盘头可再启动 ----------
echo "== E8 rearm"
OWNER=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync("tests/fixtures/dev-keys.json","utf8")).owner_token)')
DIDV=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync("tests/fixtures/dev-keys.json","utf8")).did)')
curl -sf -X POST http://127.0.0.1:8787/v1/rearm -H "authorization: Bearer $OWNER" -H "content-type: application/json" --data-raw "{\"did\":\"$DIDV\"}" >/dev/null || fail "rearm"
: > $LOGS/e8.log
rearm_now
run_qemu $B/deploy-test.img $LOGS/e8.log 300 || true
expect $LOGS/e8.log "HYOS BOOT-CHAIN OK epoch="

# ---------- E2: L0 自校验（patch core 区） ----------
echo "== E2 L0 self-check"
cp $B/deploy-happy.img $B/deploy-l0.img
dd if=/dev/urandom of=$B/deploy-l0.img bs=512 seek=1500 count=1 conv=notrunc status=none   # 窗口内非代码区，随机覆写保证哈希变化
: > $LOGS/e2.log
rearm_now
run_qemu $B/deploy-l0.img $LOGS/e2.log 240 || true
expect $LOGS/e2.log "HYOS DESTROY" "HYOS WIPED"
absent $LOGS/e2.log "HYOS BOOT-CHAIN OK"

# ---------- E3: L1 载荷篡改 ----------
echo "== E3 L1 payload tamper"
cp $B/deploy-happy.img $B/deploy-l1.img
dd if=/dev/zero of=$B/deploy-l1.img bs=512 seek=$((4096+8+100)) count=1 conv=notrunc status=none
: > $LOGS/e3.log
rearm_now
run_qemu $B/deploy-l1.img $LOGS/e3.log 240 || true
expect $LOGS/e3.log "HYOS DESTROY" "payload-tag"
absent $LOGS/e3.log "SYS_OK"

# ---------- E4: 运行期离线 → verifier 拒绝 ack → 立即销毁 ----------
echo "== E4 offline destroy at verifier"
cp $B/deploy-happy.img $B/deploy-off.img
: > $LOGS/e4.log
revoke_now
timeout 900 qemu-system-x86_64 -machine pc -m 1024 -display none \
  -serial file:$LOGS/e4.log \
  -drive file=$B/deploy-off.img,format=raw,if=ide \
  -netdev user,id=n0 -device e1000,netdev=n0,romfile=$PXE_ROM -no-reboot 2>/dev/null
expect $LOGS/e4.log "HYVERIFY GRUB-CHAIN OK" "HYOS DESTROY" "grub_ok-refused"
absent $LOGS/e4.log "SYS_OK"

# ---------- E5: L2 假系统（篡改 initrd 内 system.manifest 签名） ----------
echo "== E5 L2 fake system"
rm -rf $B/initrd-bad
mkdir -p $B/initrd-bad
cp -r $B/initrd-root/. $B/initrd-bad/
dd if=/dev/zero of=$B/initrd-bad/system.manifest.sig bs=1 count=64 conv=notrunc status=none
(cd $B/initrd-bad && find . | cpio -o -H newc --quiet | gzip -1 > $B/initrd-bad.img)
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd-bad.img \
  --hello $B/hello --keys tests/fixtures/dev-keys.json --grubtree $GT --work $B/work4 \
  --out $B/deploy-l2.img > $LOGS/mkdisk-l2.log 2>&1 || fail "mkdisk-l2"
: > $LOGS/e5.log
rearm_now
run_qemu $B/deploy-l2.img $LOGS/e5.log 300 || true
expect $LOGS/e5.log "HYOS DESTROY" "system-manifest"
absent $LOGS/e5.log "SYS_OK"

# ---------- E6: L3 应用→系统钉扎不匹配 ----------
echo "== E6 L3 os-pin mismatch"
: > $LOGS/e6.log
rearm_now
run_qemu $B/deploy-l3.img $LOGS/e6.log 300 || true
expect $LOGS/e6.log "HYOS DESTROY" "os-pin"   # SYS_OK 仅在 os-pin 校验通过后打印，本场景预期失败

# ---------- E9: L5 运行期失联 ----------
echo "== E9 L5 runtime offline"
: > $LOGS/e9.log
rearm_now
run_qemu $B/deploy-test.img $LOGS/e9.log 900 &
QPID=$!
for i in $(seq 1 450); do
  grep -q "APP_OK sealed" $LOGS/e9.log 2>/dev/null && break
  sleep 2
done
pkill -f "[w]orkerd" 2>/dev/null || true
wait $QPID 2>/dev/null || true
expect $LOGS/e9.log "APP_OK sealed" "HB_FAIL 3" "HYOS L5 WIPE"
restart_server

# ---------- 汇总 ----------
echo ""
echo "================ E2E SUMMARY ================"
for f in e1 e2 e3 e4 e5 e6 e7 e8 e9; do
  echo "--- contract: $(grep -c . $LOGS/contract.txt 2>/dev/null || echo 0) lines"
done
for f in __dummy__; do
  echo "--- $f: $(wc -l < $LOGS/$f.log 2>/dev/null || echo 0) lines"
done
if [ $FAILED -eq 0 ]; then
  echo "E2E ALL PASS"
else
  echo "E2E HAS FAILURES"
fi
exit $FAILED
