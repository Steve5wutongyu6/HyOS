#!/bin/bash
# 一机一镜像：按目标 VPS 构建专属 deploy 镜像 → 注册设备 → 上传 R2
# 每台机器独立 did/密钥/epoch —— 严禁同一镜像写入多台机器（epoch 回滚触发销毁）
#
# 用法:
#   scripts/build-for-target.sh --name vmiss-gz-01 \
#     --net-ip 1.2.3.4 --net-mask 255.255.255.0 --net-gw 1.2.3.1 \
#     --srv "IP:80@hyos.nanachi.cloud" \
#     [--key-server https://hyos.nanachi.cloud] [--ci-token XXX] [--skip-upload]
#
# 前置: build/ 下已有 core.img / vmlinuz / mkdisk 等构建产物（缺省触发全量构建）
#       VM 内需 /mnt/vmiss/gitkey_b64.txt 与 /mnt/vmiss/hyos-prod-secrets.env
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
REPO=${REPO:-/mnt/vmiss/hyos-build}
B=$REPO/build
SRC=$B/kernel

NAME=""
NET_IP=""; NET_MASK=""; NET_GW=""
SRV=""; SRV_HOST="hyos.nanachi.cloud"
KEY_SERVER="https://hyos.nanachi.cloud"
CI_TOKEN="${HYOS_CI_TOKEN:-}"
SKIP_UPLOAD=0
ACME_DOMAIN=""
ACME_STAGING=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2;;
    --net-ip) NET_IP="$2"; shift 2;;
    --net-mask) NET_MASK="$2"; shift 2;;
    --net-gw) NET_GW="$2"; shift 2;;
    --srv) SRV="$2"; shift 2;;
    --srv-host) SRV_HOST="$2"; shift 2;;
    --tls) TLS=1; shift;;
    --acme-domain) ACME_DOMAIN="$2"; shift 2;;
    --acme-staging) ACME_STAGING=1; shift;;
    --key-server) KEY_SERVER="$2"; shift 2;;
    --ci-token) CI_TOKEN="$2"; shift 2;;
    --test-mode) TEST_MODE=1; shift;;
    --skip-upload) SKIP_UPLOAD=1; shift;;
    *) echo "未知参数: $1"; exit 2;;
  esac
done
[ -n "$NAME" ] && [ -n "$NET_IP" ] && [ -n "$NET_MASK" ] && [ -n "$NET_GW" ] && [ -n "$SRV" ] \
  || { echo "用法: --name/--net-ip/--net-mask/--net-gw/--srv 必填"; exit 2; }

# 9p 缓存：宿主机侧修改的源码/产物必须 flush，否则客机读到陈旧文件（联调缺陷 #11）
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null

echo "=== 0. 构建产物检查 ==="
for f in $B/core/core.img $B/vmlinuz $B/mkdisk $B/hello; do
  [ -s "$f" ] || { echo "缺构建产物 $f —— 先全量构建（bash scripts/build-userland.sh && bash grub/build-grub.sh ...）"; exit 1; }
done

echo "=== 1. 全新设备密钥（一机一镜像）==="
cd "$REPO"
node scripts/gen-dev-keys.mjs
if [ -f /mnt/vmiss/gitkey_b64.txt ]; then export HYOS_GIT_SSH_KEY_B64=$(cat /mnt/vmiss/gitkey_b64.txt); fi
node scripts/gen-hykeys.mjs
DID=$(node scripts/fixture-field.mjs tests/fixtures/dev-keys.json did)
echo "did=$DID target=$NAME"

echo "=== 2. 注册设备到密钥服务 ==="
if [ -z "$CI_TOKEN" ] && [ -f /mnt/vmiss/hyos-prod-secrets.env ]; then
  CI_TOKEN=$(grep '^CI_TOKEN=' /mnt/vmiss/hyos-prod-secrets.env | cut -d= -f2-)
fi
[ -n "$CI_TOKEN" ] || { echo "缺 CI_TOKEN（--ci-token 或 /mnt/vmiss/hyos-prod-secrets.env）"; exit 1; }
KEY_SERVER="$KEY_SERVER" CI_TOKEN="$CI_TOKEN" node scripts/enroll-device.mjs

echo "=== 3. 用户态（嵌入设备密钥份额）==="
if [ "${TLS:-0}" = 1 ]; then
  export VERIFIER_EXTRA_FLAGS="--features tls"
fi
bash scripts/build-userland.sh > /tmp/bft-userland.log 2>&1 || { tail -10 /tmp/bft-userland.log; exit 1; }

echo "=== 3b. GRUB 重建（core.img 必须绑定新 VK/WK0，否则清单验签失败即销毁）==="
bash grub/build-grub.sh > /tmp/bft-grub.log 2>&1 || { tail -8 /tmp/bft-grub.log; exit 1; }

echo "=== 3c. hysteria2 应用（Go 静态交叉，M5）==="
if [ ! -s "$B/hysteria" ]; then
  if [ ! -d "$HOME/hysteria-src/.git" ]; then
    git clone --depth 1 --branch app/v2.14.0 https://github.com/apernet/hysteria.git "$HOME/hysteria-src" \
      || { echo "hysteria clone fail"; exit 1; }
  fi
  export PATH="$PATH:/usr/local/go/bin"
  export GOPROXY="https://goproxy.cn,direct"
  (cd "$HOME/hysteria-src/app" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.appVersion=app/v2.14.0" -o "$B/hysteria" .) \
    || { echo "hysteria build fail"; exit 1; }
fi

echo "=== 3d. 渲染生产配置（SOPS 解密机密 + 模板替换）+ 证书 ==="
export SOPS_AGE_KEY_FILE=/mnt/vmiss/hyos-age-key.txt
cd /mnt/vmiss/HysteriaConfig
sops --decrypt --input-type yaml --output-type yaml auth/users.yaml.sops > /tmp/users.dec.yaml \
  || { echo "sops decrypt fail"; exit 1; }
python3 /mnt/vmiss/hyos-build/scripts/render-hysteria-config.py
cp /tmp/app-config.yaml /tmp/bft-app-config.yaml
cp /tmp/app-auth.env /tmp/bft-app-auth.env
CERT_SRC=/tmp/tlscerts/opt/docker/nginx-proxy/certs/oa.nanachi.cloud
if [ -s "$CERT_SRC/fullchain.pem" ]; then
  cp "$CERT_SRC/fullchain.pem" /tmp/bft-tls-fullchain.pem
  cp "$CERT_SRC/key.pem" /tmp/bft-tls-key.pem
fi
[ -s /tmp/bft-tls-fullchain.pem ] && [ -s /tmp/bft-tls-key.pem ] \
  || { echo "TLS 证书缺失（先提取到 /tmp/tlscerts/）"; exit 1; }
cd "$REPO"

echo "=== 4. 清单（注入目标网络参数，签名固化）==="
TLS_ARGS=""
if [ "${TLS:-0}" = 1 ]; then
  TLS_ARGS="--tls"
fi
$B/mkdisk manifest --core $B/core/core.img --keys tests/fixtures/dev-keys.json --out-dir $B/manifests \
  --net-ip "$NET_IP" --net-mask "$NET_MASK" --net-gw "$NET_GW" --srv "$SRV" --srv-host "$SRV_HOST" $TLS_ARGS \
  ${ACME_DOMAIN:+--acme-domain "$ACME_DOMAIN"} ${ACME_STAGING:+--acme-staging}

echo "=== 5. initramfs + 镜像 ==="
bash scripts/build-initrd.sh > /tmp/bft-initrd.log 2>&1 || { tail -6 /tmp/bft-initrd.log; exit 1; }
mkdir -p $B/dist
IMG=$B/dist/deploy-$NAME.img
CFG_ARGS=""
if [ "${TEST_MODE:-0}" = 1 ]; then
  # 验证构建：2s 心跳 + E2E SUCCESS 标记（生产目标不要加 --test-mode）
  CFG_ARGS="--cfg $REPO/tests/grub-test.cfg"
fi
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img \
  --hello $B/hello --keys tests/fixtures/dev-keys.json --grubtree "$HOME/hyos-build-grub/grub-2.12" \
  --work $B/work-t-$NAME --out "$IMG" $CFG_ARGS \
  --hysteria $B/hysteria --hyauth $B/hyauth \
  --app-config /tmp/bft-app-config.yaml --auth-env /tmp/bft-app-auth.env \
  --tls-cert /tmp/bft-tls-fullchain.pem --tls-key /tmp/bft-tls-key.pem
SHA=$(sha256sum "$IMG" | awk '{print $1}')

echo "=== 6. 上传 R2 ==="
R2_KEY="hyos/targets/$NAME/deploy-$DID.img"
if [ "$SKIP_UPLOAD" = 1 ]; then
  echo "SKIP upload（--skip-upload）"
else
  : "${CLOUDFLARE_ACCOUNT_ID:=15de2210e69226938367616a4c48dee5}"
  (cd "$REPO/server" && CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:?需 CLOUDFLARE_API_TOKEN}" \
    npx -y wrangler@3.114.17 r2 object put "hyos-artifacts/$R2_KEY" -f "$IMG") \
    || { echo "R2_PUT_FAIL"; exit 1; }
  echo "r2 put done (pending remote verify)"
  (cd "$REPO/server" && npx -y wrangler@3.114.17 r2 object get "hyos-artifacts/$R2_KEY" -f /tmp/r2-target-verify.img) \
    || { echo "R2_VERIFY_GET_FAIL"; exit 1; }
  R2_SHA=$(sha256sum /tmp/r2-target-verify.img | awk '{print $1}')
  if [ "$R2_SHA" = "$SHA" ]; then
    echo "R2_VERIFIED sha256=$R2_SHA"
  else
    echo "R2_VERIFY_MISMATCH local=$SHA remote=$R2_SHA"; exit 1
  fi
fi

echo ""
echo "=== 部署单（记录到运维台账）==="
echo "target=$NAME did=$DID"
echo "net=$NET_IP/$NET_MASK gw=$NET_GW srv=$SRV"
echo "img=$IMG"
echo "sha256=$SHA"
echo "r2=hyos-artifacts/$R2_KEY"
echo "dd 命令（目标机 BIOS 模式）:"
echo "  curl -sS -H 'Authorization: Bearer <OWNER_TOKEN>' <镜像拉取地址> | dd of=/dev/vda bs=4M conv=fsync && reboot"
echo "BUILD_FOR_TARGET_OK"
