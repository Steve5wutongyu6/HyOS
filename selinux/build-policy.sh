#!/bin/bash
# 构建 SELinux 单块策略（离线合成，无需 SELinux 内核）
# 产物：build/selinux/policy —— 供 initramfs 携带、hyinit 启动时加载
set -euo pipefail
REPO=${REPO:-/mnt/vmiss/hyos-build}
OUT=$REPO/build/selinux
WORK=${WORK:-/tmp/hyospol}
mkdir -p "$OUT" "$WORK"

need="checkpolicy policycoreutils selinux-policy-dev semodule-utils"
have=1
for p in $need; do dpkg -s "$p" >/dev/null 2>&1 || have=0; done
if [ "$have" = 0 ]; then sudo apt-get install -y -qq $need >/dev/null 2>&1; fi

cd "$WORK"
cp "$REPO/selinux/hyos.te" "$REPO/selinux/hyos.fc" .
rm -f hyos.pp
make -f /usr/share/selinux/devel/Makefile hyos.pp >/tmp/hyospol-build.log 2>&1 || { tail -12 /tmp/hyospol-build.log; exit 1; }

# 合入基础策略并重建二进制策略（-n 表示不重载内核）
sudo semodule -s default -n -i "$WORK/hyos.pp" >/dev/null 2>&1 || true
sudo semodule -s default -n -B >/dev/null 2>&1 || true
POL=$(ls -1 /etc/selinux/default/policy/policy.* 2>/dev/null | sort -V | tail -1)
[ -n "$POL" ] || { echo "no merged policy found"; exit 1; }
sudo cp "$POL" "$OUT/policy"
sudo chown "$(id -u):$(id -g)" "$OUT/policy" 2>/dev/null || true

# ---- 版本对齐：目标内核支持的最高策略版本（v34 需内核 >= 6.13）----
KSRC=${KSRC:-$(ls -d $HOME/hyos-build-kernel/linux-* 2>/dev/null | sort -V | tail -1)}
SEC_H=$KSRC/security/selinux/include/security.h
V=33
if [ -f "$SEC_H" ]; then
  SYM=$(grep -oE "#define POLICYDB_VERSION_MAX POLICYDB_VERSION_[A-Z_]+" "$SEC_H" | awk "{print \$3}")
  [ -n "$SYM" ] && V=$(grep -oE "#define $SYM[[:space:]]+[0-9]+" "$SEC_H" | awk "{print \$3}")
fi
CUR=$(python3 "$REPO/selinux/policy-version.py" "$OUT/policy" 2>/dev/null || echo 0)
if [ "${CUR:-0}" -gt "$V" ]; then
  echo "WARN: policy v$CUR > kernel max v$V → 版本对齐改写（生产内核建议 >=6.13 或匹配基座策略）"
  python3 "$REPO/selinux/policy-version.py" "$OUT/policy" "$V"
fi

# ---- 自检 ----
strings "$OUT/policy" > "$WORK/policy.strings"
for t in hyos_app_t hyos_app_exec_t hyos_config_t hyos_tmp_t hyos_auth_port_t; do
  grep -qx "$t" "$WORK/policy.strings" || { echo "policy missing type: $t"; exit 1; }
done
echo "SELINUX_POLICY_OK bytes=$(stat -c %s "$OUT/policy")"