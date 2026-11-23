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

echo "=== 4. 用户态（hyinit / stubapp / mkdisk）==="
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

echo "=== 8. 注册设备到 Worker（CI 令牌）==="
if [ -n "${WORKER_URL:-}" ] && [ -n "${HYOS_CI_TOKEN:-}" ]; then
  python3 - "$WORKSPACE" "$WORKER_URL" "$HYOS_CI_TOKEN" <<PYEOF
import json, sys, urllib.request
ws, url, token = sys.argv[1], sys.argv[2], sys.argv[3]
fx = json.load(open(ws + "/tests/fixtures/dev-keys.json"))
body = json.dumps({
    "did": fx["did"], "dk_pub": fx["dk_pub_hex"], "tk_master": fx["tk_master"],
    "wk0_root": fx["wk0_root"], "wk1_root": fx["wk1_root"],
    "dek_sys": fx["dek_sys"], "dek_app": fx["dek_app"], "grub_ver_max": 1,
}).encode()
req = urllib.request.Request(url.rstrip("/") + "/v1/enroll", data=body,
                             headers={"content-type": "application/json",
                                      "authorization": "Bearer " + token})
print("enroll:", urllib.request.urlopen(req, timeout=30).read().decode()[:200])
PYEOF
else
  echo "SKIP enroll（未提供 WORKER_URL / HYOS_CI_TOKEN）"
fi

echo "=== 9. 上传 S3 ==="
if [ -n "${S3_AK:-}" ] && [ -n "${S3_SK:-}" ]; then
  export AWS_ACCESS_KEY_ID="$S3_AK" AWS_SECRET_ACCESS_KEY="$S3_SK" AWS_DEFAULT_REGION="${S3_REGION:-us-east-1}"
  KEY="hyos/$(date -u +%Y%m%d)/deploy-$DID.img"
  aws --endpoint-url "https://${S3_ENDPOINT}" s3 cp "$B/dist/deploy.img" "s3://${S3_BUCKET}/$KEY" \
    && echo "uploaded s3://${S3_BUCKET}/$KEY"
else
  echo "SKIP upload（未提供 S3 凭据）"
fi

echo "CI_BUILD_OK"