#!/bin/bash
# HyOS CI 构建（在 GitHub Actions ubuntu runner 上原生执行）
# 依赖：bash、curl、gcc-multilib、gcc-i686-linux-gnu、rustup、node、SELinux 策略工具
# 机密全部来自 GitHub Secrets，本脚本不包含任何明文凭据
set -euo pipefail

WORKSPACE=${GITHUB_WORKSPACE:-$(pwd)}
REPO_LINK=/mnt/vmiss/hyos-build
B=$WORKSPACE/build
export REPO=$WORKSPACE

# 构建脚本使用统一的挂载路径；CI 下用符号链接满足
sudo mkdir -p /mnt/vmiss
sudo ln -sfn "$WORKSPACE" "$REPO_LINK"

echo "=== 依赖检查 ==="
for t in gcc i686-linux-gnu-gcc x86_64-linux-gnu-gcc cargo node make; do
  command -v $t >/dev/null || { echo "missing tool: $t"; exit 1; }
done

echo "=== 1. 设备密钥 + 白盒密钥（签名私钥来自 Secrets）==="
cd "$WORKSPACE"
node scripts/gen-dev-keys.mjs
node scripts/gen-hykeys.mjs

echo "=== 2. 内核 ==="
bash scripts/build-kernel.sh

echo "=== 3. GRUB + hyverify ==="
bash grub/build-grub.sh

echo "=== 4. 用户态（hyinit / stubapp / mkdisk，生产启用 TLS+ACME）==="
export VERIFIER_EXTRA_FLAGS="--features tls"
bash scripts/build-userland.sh

echo "=== 5. SELinux 策略 ==="
bash selinux/build-policy.sh

echo "=== 6. 清单 / initramfs / 镜像 ==="
$B/mkdisk manifest --core $B/core/core.img --keys tests/fixtures/dev-keys.json --out-dir $B/manifests
bash scripts/build-initrd.sh
mkdir -p "$B/dist"
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img \
  --hello $B/hello --keys tests/fixtures/dev-keys.json --grubtree "$HOME/hyos-build-grub/grub-2.12" \
  --work $B/work-ci --out "$B/dist/deploy.img"

echo "=== 7. 制品元数据 ==="
sha256sum "$B/dist/deploy.img" | awk "{print \$1}" > "$B/dist/deploy.img.sha256"
DID=$(node scripts/fixture-field.mjs tests/fixtures/dev-keys.json did)
echo "did=$DID" > "$B/dist/build-info.txt"
echo "kernel=$(strings $B/vmlinuz | grep -m1 "Linux version" | head -c 80)" >> "$B/dist/build-info.txt"
cat "$B/dist/build-info.txt"

echo "=== 8. 注册设备到 Worker（CI 令牌，尽力而为）==="
# 注意：enroll 是辅助步骤（预注册设备，首启即可用）。被边缘拦截时不应阻断
# 镜像构建与 S3 上传主线 —— 失败仅告警，可用 OWNER_TOKEN 人工补注册。
if [ -n "${WORKER_URL:-}" ] && [ -n "${HYOS_CI_TOKEN:-}" ]; then
  python3 - "$WORKSPACE" "$WORKER_URL" "$HYOS_CI_TOKEN" <<PYEOF
import json, sys, urllib.request, urllib.error
ws, url, token = sys.argv[1], sys.argv[2], sys.argv[3]
fx = json.load(open(ws + "/tests/fixtures/dev-keys.json"))
body = json.dumps({
    "did": fx["did"], "dk_pub": fx["dk_pub_hex"], "tk_master": fx["tk_master"],
    "wk0_root": fx["wk0_root"], "wk1_root": fx["wk1_root"],
    "dek_sys": fx["dek_sys"], "dek_app": fx["dek_app"], "grub_ver_max": 1,
}).encode()
# 自定义 UA：默认 Python-urllib 命中 Cloudflare definitely-automated 名单，机房 IP 直接 403
req = urllib.request.Request(url.rstrip("/") + "/v1/enroll", data=body,
                             headers={"content-type": "application/json",
                                      "authorization": "Bearer " + token,
                                      "user-agent": "HyOS-CI/1.0 (enroll)"})
try:
    print("ENROLL_OK:", urllib.request.urlopen(req, timeout=30).read().decode()[:200])
except urllib.error.HTTPError as e:
    print("ENROLL_FAIL http=%s body=%s" % (e.code, e.read().decode(errors="replace")[:300]))
except Exception as e:
    print("ENROLL_FAIL net=%s" % e)
PYEOF
else
  echo "SKIP enroll（未提供 WORKER_URL / HYOS_CI_TOKEN）"
fi

echo "=== 9. 上传 R2 ==="
# Cloudflare R2（同账号 API Token，无跨境 S3 慢链路；对象路径与原 S3 布局一致）
if [ -n "${CLOUDFLARE_API_TOKEN:-}" ] && [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
  export CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID
  KEY="hyos/$(date -u +%Y%m%d)/deploy-$DID.img"
  # 钉住 3.114.17：runner 上 npx 会拉最新 4.x（要求 Node>=22 且 put 默认写本地模拟器，
  # 曾导致 "上传成功" 假象——对象只进了 runner 本地 .wrangler/state）
  (cd "$WORKSPACE/server" && npx -y wrangler@3.114.17 r2 object put "hyos-artifacts/$KEY" -f "$B/dist/deploy.img") \
    && echo "uploaded r2://hyos-artifacts/$KEY"
else
  echo "SKIP upload（未提供 CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID）"
fi

echo "CI_BUILD_OK"