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

echo "=== 3a2. 同步服务端签名密钥 + 部署前自检 ==="
# 镜像内置 SRV_PUB 来自本构建的 fixture；Worker 的 SRV_SK_PKCS8 必须与之配对，
# 否则设备在 grub_ok 响应验签失败后 fail-closed 自毁（上电即断电，VNC 空白）。
# 无论是否上传 R2 都要做（密钥配对与镜像内容无关）
if [ -n "${CLOUDFLARE_API_TOKEN:-}" ] && [ -f server/.dev.vars ]; then
  SRV_SK=$(grep "^SRV_SK_PKCS8=" server/.dev.vars | cut -d= -f2-)
  if [ -n "$SRV_SK" ]; then
    ( cd server && printf "%s" "$SRV_SK" | npx wrangler@3.114.17 secret put SRV_SK_PKCS8 >/dev/null 2>&1 ) \
      && echo "SRV_SK 已同步到 Worker" || echo "WARN: SRV_SK 同步失败"
  fi
  node scripts/verify-worker-keys.mjs || { echo "自检失败：Worker 与镜像密钥不一致，终止构建"; exit 1; }
else
  echo "跳过（缺少 CI 凭据）"
fi
echo "=== 3b. GRUB 重建（core.img 必须绑定新 VK/WK0，否则清单验签失败即销毁）==="
bash grub/build-grub.sh > /tmp/bft-grub.log 2>&1 || { tail -8 /tmp/bft-grub.log; exit 1; }

echo "=== 3c1. hyproxy（Pingora rustls 反代）==="
if [ ! -s "$B/hyproxy" ]; then
  cd "$REPO/tools/hyproxy" && CXX=x86_64-linux-gnu-g++-12 CC=x86_64-linux-gnu-gcc cargo build --release --target x86_64-unknown-linux-gnu
  cp target/x86_64-unknown-linux-gnu/release/hyproxy "$B/hyproxy"
  cd "$REPO"
fi
echo "=== 3c2. iptables-restore（源码静态交叉编译）==="
if [ ! -s "$B/iptables-restore" ]; then
  mkdir -p /tmp/ipt-src && cd /tmp/ipt-src
  [ -f iptables-1.8.11.tar.xz ] || curl -sSL -m 120 -o iptables-1.8.11.tar.xz \
    https://www.netfilter.org/projects/iptables/files/iptables-1.8.11.tar.xz
  [ -d iptables-1.8.11 ] || tar xf iptables-1.8.11.tar.xz
  cd iptables-1.8.11
  [ -f Makefile ] || CC=x86_64-linux-gnu-gcc ./configure --host=x86_64-linux-gnu \
      --prefix=/tmp/ipstatic --disable-nftables --disable-shared --enable-static \
      --with-kernel=/usr/x86_64-linux-gnu/include > /tmp/ipt-conf.log 2>&1
  # libtool 必须用 -all-static 才会真正静态链接（普通 -static 会保留 NEEDED libc）
  make -j4 LDFLAGS="-all-static" > /tmp/ipt-make.log 2>&1 || { tail -6 /tmp/ipt-make.log; exit 1; }
  cp iptables/xtables-legacy-multi "$B/iptables-restore"
  chmod +x "$B/iptables-restore"
  file "$B/iptables-restore" | grep -q "statically linked" || { echo "iptables-restore 非静态链接"; exit 1; }
  cd "$REPO"
fi
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

export HY_UPSTREAM_IP="$(echo "$SRV" | cut -d: -f1)"
echo "HY_UPSTREAM_IP=$HY_UPSTREAM_IP"
echo "=== 3d. 渲染生产配置（SOPS 解密机密 + 模板替换）+ 证书 ==="
export SOPS_AGE_KEY_FILE=/mnt/vmiss/hyos-age-key.txt
cd /mnt/vmiss/HysteriaConfig
sops --decrypt --input-type yaml --output-type yaml auth/users.yaml.sops > /tmp/users.dec.yaml \
  || { echo "sops decrypt fail"; exit 1; }
python3 /mnt/vmiss/hyos-build/scripts/render-hysteria-config.py
# render-hysteria-config.py 直接产出 /tmp/bft-*.{yaml,env,conf}
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
  ${ACME_DOMAIN:+--acme-domain "$ACME_DOMAIN"} ${ACME_STAGING:+--acme-staging} \
  ${TEST_MODE:+--test-mode --hb-ms 2000}

echo "=== 5. initramfs + 镜像 ==="
bash scripts/build-initrd.sh > /tmp/bft-initrd.log 2>&1 || { tail -6 /tmp/bft-initrd.log; exit 1; }
mkdir -p $B/dist
# EXTRA_ARGS：masquerade 组件（hyproxy/proxy.conf/porthop/iptables-restore）按产物存在与否拼接
# 内置根证书包（最小镜像无系统证书库；hyproxy 上游 TLS 校验使用）
CA_BUNDLE=$B/ca.pem
if [ ! -s "$CA_BUNDLE" ]; then
  cp /etc/ssl/certs/ca-certificates.crt "$CA_BUNDLE" 2>/dev/null || { echo "缺少 CA 包源"; exit 1; }
fi
EXTRA_ARGS=""
if [ -s "$B/hyproxy" ]; then EXTRA_ARGS="--pingora $B/hyproxy"; fi
if [ -s /tmp/bft-proxy.conf ]; then EXTRA_ARGS="$EXTRA_ARGS --proxy-conf /tmp/bft-proxy.conf"; fi
if [ -s /tmp/bft-porthop.conf ]; then EXTRA_ARGS="$EXTRA_ARGS --porthop-conf /tmp/bft-porthop.conf"; fi
if [ -s "$B/iptables-restore" ]; then EXTRA_ARGS="$EXTRA_ARGS --iptables $B/iptables-restore"; fi
if [ -s "$CA_BUNDLE" ]; then EXTRA_ARGS="$EXTRA_ARGS --ca-bundle $CA_BUNDLE"; fi
if [ -s /tmp/bft-resolv.conf ]; then EXTRA_ARGS="$EXTRA_ARGS --resolv-conf /tmp/bft-resolv.conf"; fi
IMG=$B/dist/deploy-$NAME.img
CFG_ARGS=""
if [ "${TEST_MODE:-0}" = 1 ]; then
  # 验证构建：2s 心跳 + E2E SUCCESS 标记（生产目标不要加 --test-mode）
  CFG_ARGS="--cfg $REPO/tests/grub-test.cfg"
fi
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img \
  --hello $B/hello --keys tests/fixtures/dev-keys.json --grubtree "$HOME/hyos-build-grub/grub-2.12" \
  --work $B/work-t-$NAME --out "$IMG" $CFG_ARGS \
  --hysteria $B/hysteria --hyauth $B/hyauth $EXTRA_ARGS \
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
