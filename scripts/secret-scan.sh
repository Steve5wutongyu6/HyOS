#!/bin/bash
# 提交前机密扫描：拦住不该入库的密钥/凭据（宁可误报，不可漏传）
# 用法: bash scripts/secret-scan.sh [--staged|--tree]   默认 --staged
#   退出码 0 = 通过；1 = 发现疑似机密（输出 文件:行号）
set -uo pipefail
MODE="${1:---staged}"
cd "$(git rev-parse --show-toplevel)" || exit 2

if [ "$MODE" = "--tree" ]; then
  FILES=$(git ls-files)
else
  FILES=$(git diff --cached --name-only --diff-filter=ACMR)
fi
[ -n "$FILES" ] || exit 0

# 跳过：SOPS 密文、示例文件、文档、锁文件、本脚本与白名单
CAND=$(printf "%s\n" "$FILES" \
  | grep -viE "\.(sops|example|md|lock)$|\.gitignore$" \
  | grep -vxE "scripts/secret-scan\.sh|scripts/secret-scan-allow\.list" || true)
[ -n "$CAND" ] || exit 0

# 白名单（确认为误报的路径，每行一个，可提交）
if [ -f scripts/secret-scan-allow.list ]; then
  CAND=$(printf "%s\n" "$CAND" | grep -vxF -f <(grep -vE "^#|^$" scripts/secret-scan-allow.list) || true)
  [ -n "$CAND" ] || exit 0
fi

# 高置信度机密特征（私钥块 / 云凭据 / 本项目的密钥字段）
P1='BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY'
P2='AGE-SECRET-KEY-1'
P3='gh[pousr]_[A-Za-z0-9]{30,}'
P4='cfat_[A-Za-z0-9]{20,}'
P5='"?(dk_priv_pkcs8_hex|srv_seed_hex|srv_sk|tk_master|wk0_root|wk1_root|dek_sys|dek_app)"?[[:space:]]*[:=][[:space:]]*"?[0-9a-fA-F]{32,}'
P6='SRV_SK_PKCS8=[0-9a-fA-F]{40,}'
P7='AKIA[0-9A-Z]{16}'
P8='-----BEGIN[[:space:]]+[A-Z ]*KEY-----'
PATTERNS="$P1|$P2|$P3|$P4|$P5|$P6|$P7|$P8"

HITS=$(printf "%s\n" "$CAND" | tr "\n" "\0" | xargs -0 -r grep -InE "$PATTERNS" 2>/dev/null || true)
if [ -n "$HITS" ]; then
  echo "✗ 发现疑似机密，已阻止提交：" >&2
  echo "$HITS" | sed -E "s/([0-9a-fA-F]{16})[0-9a-fA-F]{16,}/\1…(已截断)/g" >&2
  echo "" >&2
  echo "确认无害时：把路径登记到 scripts/secret-scan-allow.list（或加入 .gitignore）" >&2
  exit 1
fi
exit 0
